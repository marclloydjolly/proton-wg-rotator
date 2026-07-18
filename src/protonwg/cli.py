"""CLI entry point for `protonwg`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .commands import api as api_cmd
from .commands import health_check as health_check_cmd
from .commands import init as init_cmd
from .commands import list_cmd
from .commands import login as login_cmd
from .commands import logout as logout_cmd
from .commands import notify_setup as notify_setup_cmd
from .commands import notify_test as notify_test_cmd
from .commands import rebuild_pool as rebuild_pool_cmd
from .commands import refresh as refresh_cmd
from .commands import swap_check as swap_check_cmd
from .commands import swap_status as swap_status_cmd


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="protonwg",
        description="Maintain a rotating pool of ProtonVPN WireGuard configs.",
    )
    parser.add_argument(
        "--project-root",
        default=str(Path(__file__).resolve().parents[2]),
        help="Project root directory (default: the repository containing this script).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    login_cmd.add_subparser(subparsers)
    logout_cmd.add_subparser(subparsers)
    init_cmd.add_subparser(subparsers)
    rebuild_pool_cmd.add_subparser(subparsers)
    refresh_cmd.add_subparser(subparsers)
    list_cmd.add_subparser(subparsers)
    notify_setup_cmd.add_subparser(subparsers)
    notify_test_cmd.add_subparser(subparsers)
    swap_check_cmd.add_subparser(subparsers)
    swap_status_cmd.add_subparser(subparsers)
    health_check_cmd.add_subparser(subparsers)
    api_cmd.add_subparser(subparsers)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
