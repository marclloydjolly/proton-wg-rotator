"""
`protonwg health-check` — fast liveness probe + self-healing.

Designed to run via a 30-second systemd timer. If the internet is unreachable
through the tunnel, bring the interface down (its PostDown restores the LAN
default route), verify LAN-side reachability, then bootstrap-swap onto the best
live pool entry — and *verify the swap actually restored the internet* before
declaring success.

Anti-thrash design (added 2026-09):

* **Multi-canary.** The internet is only "down" if *all* canaries
  (default 8.8.8.8, 1.1.1.1, 9.9.9.9) fail. A single blocked resolver — e.g.
  Google throttling a Proton exit — no longer triggers a swap.
* **Failure memory.** A server whose post-swap internet check fails is
  remembered (state/health.json) and excluded from re-selection for a cooldown,
  so we stop ping-ponging back onto a well-scored-but-broken server.
* **Verify after swap.** After swapping we re-probe the internet; if it's still
  down we mark that target failed and try the next candidate, up to a limit.
* **Circuit breaker.** If too many swaps happen inside a window, stop swapping,
  leave the current tunnel in place, and log loudly instead of thrashing.

Runs as root (needed for `wg show`, `systemctl restart wg-quick@*`, and
/etc/wireguard/ writes during the recovery swap).
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
    get_current_peer_pubkey,
)
from ..health_memory import HealthMemory
from ..library import Library
from ..notifier import (
    current_hostname,
    load_config,
    safe_send_swap,
)
from ..paths import ProjectPaths
from .swap_check import _to_swap_report

DEFAULT_CANARIES = "8.8.8.8,1.1.1.1,9.9.9.9"


def _ping(target: str, *, count: int = 3, timeout: int = 2) -> bool:
    """Return True if ping to `target` succeeds on at least one probe."""
    try:
        r = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), target],
            capture_output=True,
            text=True,
            timeout=count * (timeout + 1) + 5,
        )
    except subprocess.TimeoutExpired:
        return False
    return r.returncode == 0


def _internet_up(targets: list[str], *, count: int, timeout: int) -> tuple[bool, list[str]]:
    """
    Internet is up if ANY canary replies. Returns (up, failed_targets).

    Probes in order and short-circuits on the first success, so the healthy
    path stays fast; only a total outage walks the whole list.
    """
    failed: list[str] = []
    for t in targets:
        if _ping(t, count=count, timeout=timeout):
            return True, failed
        failed.append(t)
    return False, failed


def _systemctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=30)


def _logical_id_for_pubkey(pool, pubkey: str | None) -> str | None:
    if not pubkey:
        return None
    for entry in pool:
        if entry.peer_public_key == pubkey:
            return entry.logical_id
    return None


def run(args: argparse.Namespace) -> int:
    paths = ProjectPaths.from_root(args.project_root)
    canaries = [c.strip() for c in args.canaries.split(",") if c.strip()]

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
            print(
                f"LAN gateway {lan_gateway} unreachable — not a tunnel issue, "
                "leaving wg0 alone."
            )
            return 3

    # ---- Happy path: internet works through at least one canary ---------
    up, failed = _internet_up(canaries, count=args.probe_count, timeout=args.probe_timeout)
    if up:
        return 0

    # ---- Sad path: every canary failed. Recovery starts here. -----------
    print(
        f"All {len(canaries)} canaries unreachable ({', '.join(failed)}) "
        f"[{args.probe_count} attempts each]. Initiating {args.interface} recovery."
    )

    if args.dry_run:
        print(f"(--dry-run: would stop wg-quick@{args.interface} and swap)")
        return 0

    state = HotLoopState.load(paths.hotloop_state)
    mem = HealthMemory.load(paths.health_state)

    # ---- Circuit breaker: stop thrashing --------------------------------
    recent = mem.swaps_in_window(args.swap_window_minutes)
    if recent >= args.max_swaps_per_window:
        print(
            f"CIRCUIT BREAKER: {recent} swaps in the last "
            f"{args.swap_window_minutes}m (limit {args.max_swaps_per_window}). "
            f"Leaving {args.interface} in place and NOT swapping — the pool or "
            "upstream is unstable; manual attention needed.",
            file=sys.stderr,
        )
        return 10

    # Remember which server we're leaving (it just failed its internet check),
    # so recovery won't immediately re-select it.
    if not paths.library_file.exists():
        print(f"{paths.library_file} missing — cannot select a recovery target.", file=sys.stderr)
        return 5
    lib = Library.load(paths.library_file)
    current_pubkey = get_current_peer_pubkey(args.interface)
    current_lid = _logical_id_for_pubkey(lib.pool, current_pubkey)
    if current_lid:
        mem.mark_failed(current_lid)

    # Stop the interface. Its PostDown restores the LAN default route.
    stop_r = _systemctl("stop", f"wg-quick@{args.interface}")
    if stop_r.returncode != 0:
        print(
            f"systemctl stop wg-quick@{args.interface} returned "
            f"{stop_r.returncode}: {(stop_r.stderr or stop_r.stdout).strip()}"
        )
    time.sleep(2)

    # Re-probe with wg0 down. If the internet still can't be reached, the
    # problem is LAN-side, not ours.
    up, _ = _internet_up(canaries, count=2, timeout=2)
    if not up:
        print(
            f"Still no internet after stopping {args.interface} — LAN or upstream "
            "issue, no recovery possible.",
            file=sys.stderr,
        )
        mem.save(paths.health_state)
        return 4

    from ..api import ProtonClient

    client = ProtonClient(paths.session_file)
    if not client.is_logged_in():
        print("Not logged in. Run `protonwg login` first.", file=sys.stderr)
        mem.save(paths.health_state)
        return 5

    try:
        loads = fetch_loads(client)
    except Exception as exc:
        print(f"Failed to fetch live server metrics even with LAN route: {exc}", file=sys.stderr)
        mem.save(paths.health_state)
        return 6

    # ---- Recovery loop: swap, verify internet, exclude-and-retry --------
    policy = Policy(min_improvement=0.0, min_interval_minutes=0, interface=args.interface)
    cfg = load_config(paths.notify_config)
    last_result = None
    last_decision = None

    for attempt in range(1, args.max_recovery_attempts + 1):
        exclude = mem.excluded_ids(args.failure_cooldown_minutes)
        # wg0 is down → current_pubkey None → decide() bootstraps to best not-excluded.
        decision = decide(lib.pool, loads, None, None, state, policy, exclude_logical_ids=exclude)
        if decision.target is None:
            print(f"[{decision.action.upper()}] {decision.reason}", file=sys.stderr)
            mem.save(paths.health_state)
            return 7

        print(
            f"[attempt {attempt}/{args.max_recovery_attempts}] "
            f"[{decision.action.upper()}] -> {decision.target.logical_name} "
            f"score={decision.target_metrics.score:.2f} "
            f"(excluding {len(exclude)} recently-failed)"
        )

        result = execute_swap(decision.target, paths.root, policy)
        last_result, last_decision = result, decision

        # Record the swap for the circuit breaker and email it.
        now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
        state.last_swap_at = now_iso
        state.last_swap_target_logical = decision.target.logical_name
        state.last_swap_result = (
            "ok" if result.ok else ("rolled_back" if result.rolled_back else "failed")
        )
        state.swap_count_total += 1
        state.save(paths.hotloop_state)
        mem.record_swap()

        report = _to_swap_report(decision, result, current_hostname())
        report.reason = f"[health-check recovery] {report.reason}"
        safe_send_swap(cfg, report)

        if not result.ok:
            print(
                f"Swap to {decision.target.logical_name} did not come up "
                f"({result.error}); trying next candidate.",
                file=sys.stderr,
            )
            mem.mark_failed(decision.target.logical_id)
            mem.save(paths.health_state)
            continue

        # Handshake is up — but does the internet actually work now?
        up, still_failed = _internet_up(canaries, count=4, timeout=2)
        if up:
            print(
                f"RECOVERED -> {decision.target.logical_name} "
                f"({decision.target.endpoint_ip}) handshake "
                f"{result.handshake_age_after_s}s, internet verified."
            )
            mem.save(paths.health_state)
            return 0

        print(
            f"Swapped to {decision.target.logical_name} and it handshook, but "
            f"internet still down ({', '.join(still_failed)}) — marking it failed "
            "and trying the next candidate.",
            file=sys.stderr,
        )
        mem.mark_failed(decision.target.logical_id)
        mem.save(paths.health_state)

    print(
        f"Recovery exhausted after {args.max_recovery_attempts} attempts; "
        "internet still down. Leaving the last target in place.",
        file=sys.stderr,
    )
    if last_result and last_result.ok:
        return 0
    if last_result and last_result.rolled_back:
        return 8
    return 9


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "health-check",
        help=(
            "Multi-canary liveness probe — if the internet is unreachable, bring "
            "the tunnel down and bootstrap-swap to a verified-working pool entry."
        ),
    )
    p.add_argument(
        "--canaries",
        default=DEFAULT_CANARIES,
        help=f"Comma-separated canary IPs; internet is 'down' only if all fail (default {DEFAULT_CANARIES}).",
    )
    p.add_argument(
        "--probe-target",
        default=None,
        help="Deprecated single-canary alias; if set, prepended to --canaries.",
    )
    p.add_argument("--probe-count", type=int, default=3, help="Ping attempts per canary (default 3).")
    p.add_argument("--probe-timeout", type=int, default=2, help="Per-probe timeout seconds (default 2).")
    p.add_argument(
        "--max-recovery-attempts",
        type=int,
        default=3,
        help="How many candidates to try (with internet verify) before giving up (default 3).",
    )
    p.add_argument(
        "--failure-cooldown-minutes",
        type=int,
        default=20,
        help="Exclude a server from re-selection this long after it fails a check (default 20).",
    )
    p.add_argument(
        "--max-swaps-per-window",
        type=int,
        default=4,
        help="Circuit breaker: stop swapping after this many swaps in the window (default 4).",
    )
    p.add_argument(
        "--swap-window-minutes",
        type=int,
        default=30,
        help="Circuit-breaker window in minutes (default 30).",
    )
    p.add_argument(
        "--lan-gateway",
        default=None,
        help="LAN gateway to sanity-check before acting; auto-read from library.json if omitted.",
    )
    p.add_argument("--interface", default="wg0")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without stopping the interface or swapping.",
    )

    def _run(args: argparse.Namespace) -> int:
        # Fold a deprecated --probe-target into the canary list.
        if args.probe_target:
            args.canaries = f"{args.probe_target},{args.canaries}"
        return run(args)

    p.set_defaults(func=_run)
