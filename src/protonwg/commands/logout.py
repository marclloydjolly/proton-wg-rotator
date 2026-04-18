"""`protonwg logout` — drop cached session."""

from __future__ import annotations

import argparse

from ..api import ProtonClient
from ..paths import ProjectPaths


def run(args: argparse.Namespace) -> int:
    paths = ProjectPaths.from_root(args.project_root)
    client = ProtonClient(paths.session_file)
    client.logout()
    print("Session cleared.")
    return 0


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("logout", help="Drop cached Proton session.")
    p.set_defaults(func=run)
