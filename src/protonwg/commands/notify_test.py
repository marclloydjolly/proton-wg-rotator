"""`protonwg notify-test` — send a synthetic refresh report to verify SMTP."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone

from ..notifier import (
    PoolChange,
    RefreshReport,
    current_hostname,
    load_config,
    send,
)
from ..paths import ProjectPaths


def run(args: argparse.Namespace) -> int:
    paths = ProjectPaths.from_root(args.project_root)
    cfg = load_config(paths.notify_config)
    if cfg is None:
        print(
            f"{paths.notify_config} missing. Run `protonwg notify-setup` first.",
            file=sys.stderr,
        )
        return 1
    if not cfg.enabled:
        print("Notifier is disabled in notify.toml (enabled = false).", file=sys.stderr)
        return 1

    now = datetime.now(timezone.utc)
    report = RefreshReport(
        host=current_hostname(),
        library_path=str(paths.library_file),
        started_at=now - timedelta(seconds=2),
        finished_at=now,
        exit_code=0,
        cert_serial="SYNTHETIC-12345",
        cert_expires_at=(now + timedelta(days=300)).isoformat(timespec="seconds"),
        cert_days_remaining=300,
        cert_rotated=False,
        pool_size=15,
        changes=[
            PoolChange(
                index=5,
                kind="replaced",
                before="UK#421 146.70.180.11",
                after="UK#502 146.70.181.22",
                reason="UK#421 went offline",
            ),
            PoolChange(
                index=9,
                kind="endpoint_ip",
                before="UK#300 146.70.179.34",
                after="UK#300 146.70.179.41",
                reason="Proton moved the physical endpoint IP",
            ),
        ],
        warnings=["This is a synthetic test email; no real refresh was run."],
        summary_line="Synthetic report from `protonwg notify-test`.",
    )

    try:
        send(cfg, report)
    except Exception as exc:
        print(f"Test send FAILED: {exc}", file=sys.stderr)
        return 1
    print(f"Test email sent to {cfg.email.to_address} via {cfg.smtp.host}:{cfg.smtp.port}")
    return 0


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "notify-test", help="Send a synthetic refresh report via the configured SMTP."
    )
    p.set_defaults(func=run)
