"""`protonwg swap-status` — human-readable preview of the next swap-check."""

from __future__ import annotations

import argparse
import sys

from ..hotloop import (
    HotLoopState,
    Policy,
    decide,
    fetch_loads,
    get_current_peer_pubkey,
    get_handshake_age_seconds,
)
from ..library import Library
from ..paths import ProjectPaths


def run(args: argparse.Namespace) -> int:
    paths = ProjectPaths.from_root(args.project_root)
    if not paths.library_file.exists():
        print(f"{paths.library_file} missing.", file=sys.stderr)
        return 1
    lib = Library.load(paths.library_file)
    state = HotLoopState.load(paths.hotloop_state)
    policy = Policy(
        min_improvement=args.min_improvement / 100.0,
        min_interval_minutes=args.min_interval_minutes,
        interface=args.interface,
    )

    pubkey = get_current_peer_pubkey(policy.interface)
    age = get_handshake_age_seconds(policy.interface)
    cur_entry = next((e for e in lib.pool if e.peer_public_key == pubkey), None)

    print(f"Interface  : {policy.interface}")
    print(f"Peer pubkey: {pubkey or '<no interface or no peer>'}")
    print(f"Handshake  : {age}s ago" if age is not None else "Handshake  : never")
    if cur_entry:
        print(f"Pool match : #{cur_entry.index} {cur_entry.logical_name} ({cur_entry.endpoint_ip})")
    else:
        print("Pool match : <NOT IN POOL — next check would bootstrap-swap>")
    print()
    print("State:")
    print(f"  last_swap_at      : {state.last_swap_at or '<never>'}")
    print(f"  last_swap_target  : {state.last_swap_target_logical or '<none>'}")
    print(f"  last_swap_result  : {state.last_swap_result or '<none>'}")
    print(f"  swap_count_total  : {state.swap_count_total}")
    print()
    print("Policy:")
    print(f"  min_improvement    : {policy.min_improvement:.0%}")
    print(f"  min_interval       : {policy.min_interval_minutes}m")
    print(f"  dead_handshake     : {policy.dead_handshake_seconds}s")
    print(f"  rollback_wait      : {policy.rollback_wait_seconds}s")
    print()

    try:
        loads = fetch_loads()
    except Exception as exc:
        print(f"Could not fetch /vpn/loads: {exc}", file=sys.stderr)
        return 1

    decision = decide(lib.pool, loads, pubkey, age, state, policy)

    print(f"Next swap-check decision: [{decision.action.upper()}]")
    print(f"  {decision.reason}")
    print()
    print("Top 10 pool candidates (live Score, lower is better):")
    print(f"  {'#':>3} {'Logical':<10} {'Score':>6} {'Load':>5} {'Status':>7} {'Endpoint':<18}")
    print(f"  {'-' * 58}")
    for c in decision.ranked[:10]:
        marker = "  <- current" if c.is_current else ""
        status_word = "live" if c.metrics.status == 1 else "DEAD"
        print(
            f"  {c.entry.index:>3} {c.entry.logical_name:<10} "
            f"{c.metrics.score:>6.2f} {c.metrics.load:>4}% {status_word:>7} "
            f"{c.entry.endpoint_ip:<18}{marker}"
        )
    return 0


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "swap-status",
        help="Preview what the next swap-check would do, plus the top candidates.",
    )
    p.add_argument("--interface", default="wg0")
    p.add_argument("--min-improvement", type=float, default=20.0)
    p.add_argument("--min-interval-minutes", type=int, default=30)
    p.set_defaults(func=run)
