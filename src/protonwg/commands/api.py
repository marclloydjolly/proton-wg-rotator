"""`protonwg api` — long-running HTTP server for frontend integration."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from ..apiserver import serve


def run(args: argparse.Namespace) -> int:
    # Env var provides a token override without a CLI flag; useful for
    # systemd `Environment=` lines that keep the token out of ps output.
    token = args.auth_token or os.environ.get("PROTONWG_API_TOKEN") or None
    return serve(
        project_root=Path(args.project_root),
        bind_host=args.bind_host,
        bind_port=args.bind_port,
        iface=args.interface,
        cache_ttl=args.cache_ttl,
        auth_token=token,
        no_auth=args.no_auth,
    )


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "api",
        help=(
            "Run a small HTTP API for frontend integration. Long-running; "
            "deploy under systemd. Auth is required whenever the bind is not "
            "loopback."
        ),
    )
    p.add_argument(
        "--bind-host",
        default="127.0.0.1",
        help=(
            "Interface to bind. Loopback (default) skips auth for same-host "
            "trust. Any other address (e.g. a LAN IP or 0.0.0.0) turns on "
            "bearer-token auth using state/api-token."
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
            "Proton; lower = fresher data. Default 1.0."
        ),
    )
    p.add_argument(
        "--auth-token",
        default=None,
        help=(
            "Explicit bearer token. If omitted on a non-loopback bind, the "
            "token in state/api-token is used (auto-generated on first run). "
            "Also readable from the PROTONWG_API_TOKEN env var."
        ),
    )
    p.add_argument(
        "--no-auth",
        action="store_true",
        help=(
            "Disable auth even on a non-loopback bind. Only use if you fully "
            "trust every device on the network you're binding to."
        ),
    )
    p.set_defaults(func=run)
