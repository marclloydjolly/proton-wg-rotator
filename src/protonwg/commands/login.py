"""`protonwg login` — interactive SRP login, caches session to state/session.json."""

from __future__ import annotations

import argparse
import getpass
import sys

from ..api import ProtonAPIError, ProtonClient
from ..paths import ProjectPaths


def run(args: argparse.Namespace) -> int:
    paths = ProjectPaths.from_root(args.project_root)
    client = ProtonClient(paths.session_file)

    if client.is_logged_in() and not args.force:
        print(
            f"Already logged in (session at {paths.session_file}). "
            "Use --force to re-authenticate.",
            file=sys.stderr,
        )
        return 0

    username = args.username or input("Proton username: ").strip()
    password = getpass.getpass("Proton password: ")

    try:
        client.login(username, password)
    except ProtonAPIError as exc:
        print(f"Login failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        # proton-client raises various SRP exceptions; surface them plainly.
        print(f"Login failed: {exc}", file=sys.stderr)
        return 1

    print(f"Logged in. Session cached at {paths.session_file}")
    return 0


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("login", help="Authenticate with Proton and cache session.")
    p.add_argument("--username", help="Proton username (prompted if omitted).")
    p.add_argument(
        "--force", action="store_true", help="Re-authenticate even if a session exists."
    )
    p.set_defaults(func=run)
