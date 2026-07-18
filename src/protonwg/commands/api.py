"""`protonwg api` — long-running HTTP server for frontend integration."""

from __future__ import annotations

import argparse
from pathlib import Path

from ..apiserver import serve


def run(args: argparse.Namespace) -> int:
    return serve(
        project_root=Path(args.project_root),
        bind_host=args.bind_host,
        bind_port=args.bind_port,
        iface=args.interface,
        cache_ttl=args.cache_ttl,
    )


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "api",
        help=(
            "Run a small HTTP API on localhost so a frontend can inspect "
            "state and trigger actions. Long-running; deploy under systemd."
        ),
    )
    p.add_argument(
        "--bind-host",
        default="127.0.0.1",
        help=(
            "Interface to bind (default 127.0.0.1). No auth — do NOT bind to "
            "0.0.0.0 unless you've put an auth layer in front."
        ),
    )
    p.add_argument("--bind-port", type=int, default=8787)
    p.add_argument("--interface", default="wg0", help="WG interface to inspect.")
    p.add_argument(
        "--cache-ttl",
        type=float,
        default=1.0,
        help=(
            "Seconds to cache /state and derived reads. Higher = kinder to "
            "Proton's /vpn/loads; lower = fresher data. Default 1.0."
        ),
    )
    p.set_defaults(func=run)
