"""`protonwg list` — show current pool and cert status."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from ..library import Library
from ..paths import ProjectPaths


def _format_expiry(iso: str) -> str:
    expires = datetime.fromisoformat(iso)
    delta = expires - datetime.now(timezone.utc)
    days = int(delta.total_seconds() / 86400)
    return f"{iso}  ({days}d remaining)"


def run(args: argparse.Namespace) -> int:
    paths = ProjectPaths.from_root(args.project_root)
    if not paths.library_file.exists():
        print(f"{paths.library_file} does not exist. Run `protonwg init` first.")
        return 1
    lib = Library.load(paths.library_file)

    print(f"Library: {paths.library_file}")
    print(f"Generated: {lib.generated_at}")
    print(f"Filters: {lib.filters}")
    if lib.identity is not None:
        print(f"Cert serial: {lib.identity.cert_serial}")
        print(f"Cert expires: {_format_expiry(lib.identity.cert_expires_at)}")
    print(f"Pool size: {len(lib.pool)}")
    print()
    fmt = "{:>3}  {:<14}  {:<16}  {:<16}  {:<4}  {}"
    print(fmt.format("#", "Logical", "City", "Endpoint", "Tier", "Config"))
    print("-" * 88)
    for entry in lib.pool:
        endpoint = f"{entry.endpoint_ip}:{entry.endpoint_port}"
        print(
            fmt.format(
                entry.index,
                entry.logical_name[:14],
                entry.city[:16],
                endpoint[:16],
                entry.tier,
                entry.config_file,
            )
        )
    return 0


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("list", help="Show the current pool and cert status.")
    p.set_defaults(func=run)
