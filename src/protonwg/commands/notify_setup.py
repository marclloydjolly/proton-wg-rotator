"""`protonwg notify-setup` — interactively write state/notify.toml."""

from __future__ import annotations

import argparse

from ..notifier import write_config_interactively
from ..paths import ProjectPaths


def run(args: argparse.Namespace) -> int:
    paths = ProjectPaths.from_root(args.project_root)
    if paths.notify_config.exists() and not args.force:
        print(
            f"{paths.notify_config} already exists. Use --force to overwrite."
        )
        return 1
    write_config_interactively(paths.notify_config)
    print(f"Wrote {paths.notify_config} (chmod 600).")
    return 0


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "notify-setup",
        help="Interactively configure SMTP notification settings.",
    )
    p.add_argument(
        "--force", action="store_true", help="Overwrite an existing notify.toml."
    )
    p.set_defaults(func=run)
