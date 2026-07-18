"""`protonwg swap-check` — timer-fired decide+maybe-swap."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from ..hotloop import (
    HotLoopState,
    Policy,
    decide,
    execute_swap,
    fetch_loads,
    get_current_peer_pubkey,
    get_handshake_age_seconds,
)
from ..library import Library
from ..notifier import (
    SwapReport,
    current_hostname,
    load_config,
    safe_send_swap,
)
from ..paths import ProjectPaths


def _to_swap_report(decision, result, host) -> SwapReport:
    """Flatten Decision + SwapResult into the notifier's SwapReport shape."""
    top = []
    for c in decision.ranked[:5]:
        top.append(
            (
                c.entry.logical_name,
                c.metrics.score,
                c.metrics.load,
                c.entry.endpoint_ip,
                c.is_current,
            )
        )
    before_name = decision.current_entry.logical_name if decision.current_entry else "<not in pool>"
    before_ip = decision.current_entry.endpoint_ip if decision.current_entry else "unknown"
    before_score = decision.current_metrics.score if decision.current_metrics else None
    before_load = decision.current_metrics.load if decision.current_metrics else None
    target = decision.target
    target_metrics = decision.target_metrics
    assert target is not None and target_metrics is not None, "swap report needs a target"
    return SwapReport(
        host=host,
        when=datetime.now(timezone.utc),
        action=decision.action,
        reason=decision.reason,
        before_name=before_name,
        before_ip=before_ip,
        before_score=before_score,
        before_load=before_load,
        before_handshake_age_s=decision.current_handshake_age_s,
        after_name=target.logical_name,
        after_ip=target.endpoint_ip,
        after_score=target_metrics.score,
        after_load=target_metrics.load,
        improvement=decision.improvement,
        result_ok=result.ok,
        rolled_back=result.rolled_back,
        error=result.error,
        duration_ms=result.duration_ms,
        handshake_age_after_s=result.handshake_age_after_s,
        top_candidates=top,
    )


def run(args: argparse.Namespace) -> int:
    paths = ProjectPaths.from_root(args.project_root)
    if not paths.library_file.exists():
        print(f"{paths.library_file} missing. Run `protonwg init` first.", file=sys.stderr)
        return 1
    lib = Library.load(paths.library_file)
    state = HotLoopState.load(paths.hotloop_state)
    policy = Policy(
        min_improvement=args.min_improvement / 100.0,
        min_interval_minutes=args.min_interval_minutes,
        interface=args.interface,
    )

    current_pubkey = get_current_peer_pubkey(policy.interface)
    handshake_age = get_handshake_age_seconds(policy.interface)

    from ..api import ProtonClient

    client = ProtonClient(paths.session_file)
    if not client.is_logged_in():
        print(
            "Not logged in. Run `protonwg login` first.",
            file=sys.stderr,
        )
        return 1

    try:
        loads = fetch_loads(client)
    except Exception as exc:
        print(f"Failed to fetch live server metrics: {exc}", file=sys.stderr)
        return 1

    decision = decide(lib.pool, loads, current_pubkey, handshake_age, state, policy)

    # Log one line per candidate so journalctl shows the full picture.
    print(f"[{decision.action.upper()}] {decision.reason}")
    if decision.current_entry and decision.current_metrics:
        print(
            f"  current : {decision.current_entry.logical_name} "
            f"score={decision.current_metrics.score:.2f} "
            f"load={decision.current_metrics.load}% "
            f"handshake={handshake_age}s ago"
        )
    if decision.target and decision.target_metrics:
        print(
            f"  target  : {decision.target.logical_name} "
            f"score={decision.target_metrics.score:.2f} "
            f"load={decision.target_metrics.load}%"
        )

    if decision.action in ("stay", "error"):
        return 0 if decision.action == "stay" else 1

    if args.dry_run:
        print("(--dry-run: not actually swapping)")
        return 0

    # Execute.
    result = execute_swap(decision.target, paths.root, policy)

    # Update state.
    now_iso = datetime.now(timezone.utc).isoformat(timespec="seconds")
    state.last_swap_at = now_iso
    state.last_swap_target_logical = decision.target.logical_name
    state.last_swap_result = "ok" if result.ok else ("rolled_back" if result.rolled_back else "failed")
    state.swap_count_total += 1
    state.save(paths.hotloop_state)

    # Email.
    cfg = load_config(paths.notify_config)
    report = _to_swap_report(decision, result, current_hostname())
    safe_send_swap(cfg, report)

    if result.ok:
        print(
            f"SWAP OK -> {decision.target.logical_name} "
            f"({decision.target.endpoint_ip}) handshake {result.handshake_age_after_s}s "
            f"duration {result.duration_ms}ms"
        )
        return 0
    if result.rolled_back:
        print(f"SWAP ROLLED BACK: {result.error}", file=sys.stderr)
        return 2
    print(f"SWAP FAILED (no rollback): {result.error}", file=sys.stderr)
    return 3


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "swap-check",
        help="Check /vpn/loads and swap wg0 to the best pool entry if warranted.",
    )
    p.add_argument("--interface", default="wg0")
    p.add_argument(
        "--min-improvement",
        type=float,
        default=20.0,
        help="Minimum %% score improvement required to swap (default 20).",
    )
    p.add_argument(
        "--min-interval-minutes",
        type=int,
        default=30,
        help="Minimum minutes between swaps (default 30).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the decision but do not actually swap.",
    )
    p.set_defaults(func=run)
