"""
`protonwg health-check` — fast liveness probe + self-healing.

Designed to run via a 30-second systemd timer. If a simple ICMP ping to
PROBE_TARGET fails, bring the interface down (its PostDown restores the
LAN default route), verify LAN-side reachability, then invoke the normal
swap-check logic with zero thresholds to force a bootstrap-swap onto the
best live pool entry.

This exists because `swap-check` itself depends on reaching Proton's
API — and when the interface under management IS the default route and
it's dead, that API is unreachable. `health-check` breaks that cycle.

Runs as root (needed for `wg show`, `systemctl restart wg-quick@*`,
and /etc/wireguard/ writes during the recovery swap).
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from datetime import datetime, timezone

from ..hotloop import (
    HotLoopState,
    Policy,
    decide,
    execute_swap,
    fetch_loads,
)
from ..library import Library
from ..notifier import (
    current_hostname,
    load_config,
    safe_send_swap,
)
from ..paths import ProjectPaths
from .swap_check import _to_swap_report


def _ping(target: str, *, count: int = 3, timeout: int = 2) -> bool:
    """Return True if ping succeeds on at least one probe."""
    r = subprocess.run(
        ["ping", "-c", str(count), "-W", str(timeout), target],
        capture_output=True,
        text=True,
        timeout=count * (timeout + 1) + 5,
    )
    return r.returncode == 0


def _systemctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["systemctl", *args], capture_output=True, text=True, timeout=30
    )


def run(args: argparse.Namespace) -> int:
    paths = ProjectPaths.from_root(args.project_root)

    # Figure out the LAN gateway: explicit flag wins, else pull from the
    # library's router-mode render config if present.
    lan_gateway = args.lan_gateway
    if not lan_gateway and paths.library_file.exists():
        try:
            lib_probe = Library.load(paths.library_file)
            lan_gateway = (lib_probe.render or {}).get("router", {}).get("lan_gateway")
        except Exception:
            lan_gateway = None

    # ---- LAN sanity check ---------------------------------------------
    if lan_gateway:
        if not _ping(lan_gateway, count=1, timeout=1):
            # LAN itself is unreachable — the box has bigger problems than
            # wg0. Don't touch the tunnel; a reactive swap can't fix this.
            print(
                f"LAN gateway {lan_gateway} unreachable — not a tunnel issue, "
                "leaving wg0 alone."
            )
            return 3

    # ---- Happy path: internet works ------------------------------------
    if _ping(
        args.probe_target,
        count=args.probe_count,
        timeout=args.probe_timeout,
    ):
        # Tunnel is healthy (or at least routing internet traffic). Done.
        return 0

    # ---- Sad path: probe failed. Recovery starts here. -----------------
    print(
        f"Internet probe to {args.probe_target} failed "
        f"({args.probe_count} attempts, {args.probe_timeout}s each). "
        f"Initiating {args.interface} recovery."
    )

    if args.dry_run:
        print(f"(--dry-run: would stop wg-quick@{args.interface} and swap)")
        return 0

    # Stop the interface. Its PostDown restores the LAN default route via
    # the router-mode template we installed at init time.
    stop_r = _systemctl("stop", f"wg-quick@{args.interface}")
    if stop_r.returncode != 0:
        # Not fatal — the unit may already be stopped or never existed.
        print(
            f"systemctl stop wg-quick@{args.interface} returned "
            f"{stop_r.returncode}: {(stop_r.stderr or stop_r.stdout).strip()}"
        )

    # Give the kernel a moment to settle routes + DNS.
    time.sleep(2)

    # Re-probe. If we still can't reach the internet with wg0 down, the
    # problem is LAN-side, not ours. Bail loudly.
    if not _ping(args.probe_target, count=2, timeout=2):
        print(
            f"Still cannot reach {args.probe_target} after stopping "
            f"{args.interface} — LAN or upstream issue, no recovery possible.",
            file=sys.stderr,
        )
        return 4

    # ---- Fetch loads and bootstrap-swap --------------------------------
    if not paths.library_file.exists():
        print(
            f"{paths.library_file} missing — cannot select a recovery target.",
            file=sys.stderr,
        )
        return 5

    lib = Library.load(paths.library_file)
    state = HotLoopState.load(paths.hotloop_state)
    # Zero thresholds: this is a recovery, not an optimisation.
    policy = Policy(
        min_improvement=0.0,
        min_interval_minutes=0,
        interface=args.interface,
    )

    try:
        loads = fetch_loads()
    except Exception as exc:
        print(
            f"Failed to fetch /vpn/loads even with LAN route: {exc}",
            file=sys.stderr,
        )
        return 6

    # wg0 is down so get_current_peer_pubkey returns None → decide() returns
    # bootstrap_swap targeting the best candidate.
    decision = decide(lib.pool, loads, None, None, state, policy)

    if decision.target is None:
        print(
            f"[{decision.action.upper()}] {decision.reason}",
            file=sys.stderr,
        )
        return 7

    print(f"[{decision.action.upper()}] {decision.reason}")
    if decision.target_metrics:
        print(
            f"  target: {decision.target.logical_name} "
            f"score={decision.target_metrics.score:.2f} "
            f"load={decision.target_metrics.load}%"
        )

    result = execute_swap(decision.target, paths.root, policy)

    # Update state (so optimisation-phase cooldowns are correctly reset).
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    state.last_swap_at = now_iso
    state.last_swap_target_logical = decision.target.logical_name
    state.last_swap_result = (
        "ok" if result.ok else ("rolled_back" if result.rolled_back else "failed")
    )
    state.swap_count_total += 1
    state.save(paths.hotloop_state)

    # Email the recovery event. Prefix the reason so it's obvious in the
    # inbox that this was reactive, not optimisation-driven.
    cfg = load_config(paths.notify_config)
    report = _to_swap_report(decision, result, current_hostname())
    report.reason = f"[health-check recovery] {report.reason}"
    safe_send_swap(cfg, report)

    if result.ok:
        print(
            f"RECOVERED -> {decision.target.logical_name} "
            f"({decision.target.endpoint_ip}) "
            f"handshake {result.handshake_age_after_s}s, "
            f"duration {result.duration_ms}ms"
        )
        return 0
    if result.rolled_back:
        print(f"RECOVERY ROLLED BACK: {result.error}", file=sys.stderr)
        return 8
    print(f"RECOVERY FAILED: {result.error}", file=sys.stderr)
    return 9


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "health-check",
        help=(
            "Fast liveness probe — if ping fails, bring the tunnel down and "
            "bootstrap-swap to the best pool entry."
        ),
    )
    p.add_argument(
        "--probe-target",
        default="8.8.8.8",
        help="IP to ping as the internet canary (default 8.8.8.8).",
    )
    p.add_argument(
        "--probe-count",
        type=int,
        default=3,
        help="Number of ping probes to send (default 3).",
    )
    p.add_argument(
        "--probe-timeout",
        type=int,
        default=2,
        help="Per-probe timeout in seconds (default 2).",
    )
    p.add_argument(
        "--lan-gateway",
        default=None,
        help=(
            "LAN gateway to sanity-check before acting on the tunnel. "
            "Auto-read from library.json if omitted."
        ),
    )
    p.add_argument("--interface", default="wg0")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without stopping the interface or swapping.",
    )
    p.set_defaults(func=run)
