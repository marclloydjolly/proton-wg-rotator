"""
`protonwg refresh` — daily maintenance.

Does three things:
  1. If the cert is within `--cert-refresh-days` of expiry, re-issue it
     against the existing identity (WG private key stays the same).
  2. Fetches fresh logicals; for any pool entry whose logical is gone /
     offline, replace it with a best-scoring alternative that satisfies the
     original filters and isn't already in the pool.
  3. Re-renders every config file from the current manifest. Endpoint IPs or
     peer pubkeys occasionally change server-side, so this is cheap to do
     unconditionally.

Also builds a RefreshReport and, if `state/notify.toml` is configured,
e-mails it. Notifier failures never fail the refresh itself.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..api import ProtonAPIError, ProtonClient
from ..crypto import load_identity
from ..library import DEFAULT_WG_ADDRESS, Library, PoolEntry
from ..notifier import (
    NotifyConfig,
    PoolChange,
    RefreshReport,
    current_hostname,
    load_config,
    safe_send,
)
from ..paths import ProjectPaths
from ..selection import logical_passes_filter, normalise_logical, select_pool
from ..wg import RouterParams, write_config


def _load_library_or_die(lib_path: Path) -> Library:
    if not lib_path.exists():
        print(f"{lib_path} does not exist. Run `protonwg init` first.", file=sys.stderr)
        sys.exit(1)
    return Library.load(lib_path)


def _cert_needs_rotation(lib: Library, within_days: int) -> bool:
    if lib.identity is None:
        return True
    expires = datetime.fromisoformat(lib.identity.cert_expires_at)
    threshold = datetime.now(timezone.utc) + timedelta(days=within_days)
    return expires <= threshold


def _days_remaining(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    return int((dt - datetime.now(timezone.utc)).total_seconds() // 86400)


def _reissue_cert(
    client: ProtonClient, paths: ProjectPaths, lib: Library, device_name: str | None
) -> None:
    assert lib.identity is not None
    pub_pem = (paths.root / lib.identity.ed25519_public_pem_path).read_text()
    device = device_name or f"protonwg-{socket.gethostname()}-{int(time.time())}"
    cert = client.register_certificate(pub_pem, device_name=device)
    (paths.root / lib.identity.cert_pem_path).write_text(cert.certificate_pem)
    (paths.root / lib.identity.cert_pem_path).chmod(0o600)
    lib.identity.cert_serial = cert.serial_number
    lib.identity.cert_expires_at = datetime.fromtimestamp(
        cert.expiration_time, tz=timezone.utc
    ).isoformat(timespec="seconds")


def _do_refresh(
    args: argparse.Namespace, report: RefreshReport
) -> int:
    paths = ProjectPaths.from_root(args.project_root)
    report.library_path = str(paths.library_file)
    lib = _load_library_or_die(paths.library_file)
    report.pool_size = len(lib.pool)

    client = ProtonClient(paths.session_file)
    if not client.is_logged_in():
        report.error = "Not logged in. Run `protonwg login` first."
        print(report.error, file=sys.stderr)
        return 1

    changed = False

    # ---- step 1: cert rotation ------------------------------------------
    if _cert_needs_rotation(lib, args.cert_refresh_days):
        before_expires = lib.identity.cert_expires_at if lib.identity else "<none>"
        print(f"Cert expires {before_expires}; rotating.")
        try:
            _reissue_cert(client, paths, lib, args.device_name)
            changed = True
            report.cert_rotated = True
        except ProtonAPIError as exc:
            report.error = f"Cert rotation failed: {exc}"
            print(report.error, file=sys.stderr)
            return 1

    if lib.identity:
        report.cert_serial = lib.identity.cert_serial
        report.cert_expires_at = lib.identity.cert_expires_at
        report.cert_days_remaining = _days_remaining(lib.identity.cert_expires_at)

    # ---- step 2: pool health --------------------------------------------
    try:
        logicals = client.get_logicals()
    except ProtonAPIError as exc:
        report.error = f"Failed to list logicals: {exc}"
        print(report.error, file=sys.stderr)
        return 1

    by_id = {lg["ID"]: lg for lg in logicals}
    current_ids = {e.logical_id for e in lib.pool}
    filters = lib.filters or {}
    country = filters.get("country", "UK")
    city = filters.get("city", "London")
    max_tier = int(filters.get("max_tier", 2))
    target_size = len(lib.pool) or 15
    candidates = select_pool(
        logicals,
        country=country,
        city=city,
        max_tier=max_tier,
        size=max(target_size * 3, 50),
    )

    new_pool: list[PoolEntry] = []
    for entry in lib.pool:
        logical = by_id.get(entry.logical_id)
        # "Still OK" means the logical is online AND still matches the pool's
        # original filters. Whether it's currently in the top-N by Score is
        # irrelevant — tiny score drifts would otherwise cause phantom
        # replacements every run.
        still_ok = logical is not None and logical_passes_filter(
            logical, country=country, city=city, max_tier=max_tier
        )
        if still_ok:
            fresh = normalise_logical(logical)
            if fresh is None:
                # Physical picker couldn't find an online server within this
                # logical — treat as dead and fall through to replacement.
                still_ok = False
        if still_ok:
            assert fresh is not None  # for type-checker
            updated = PoolEntry(
                index=entry.index,
                logical_id=fresh["logical_id"],
                logical_name=fresh["logical_name"],
                country=fresh["country"],
                city=fresh["city"],
                tier=fresh["tier"],
                features=fresh["features"],
                physical_id=fresh["physical_id"],
                endpoint_ip=fresh["endpoint_ip"],
                endpoint_port=fresh["endpoint_port"],
                peer_public_key=fresh["peer_public_key"],
                config_file=entry.config_file,
            )
            if updated.endpoint_ip != entry.endpoint_ip:
                report.changes.append(
                    PoolChange(
                        index=entry.index,
                        kind="endpoint_ip",
                        before=f"{entry.logical_name} {entry.endpoint_ip}",
                        after=f"{updated.logical_name} {updated.endpoint_ip}",
                        reason="Proton moved the physical endpoint IP",
                    )
                )
                changed = True
            if updated.peer_public_key != entry.peer_public_key:
                report.changes.append(
                    PoolChange(
                        index=entry.index,
                        kind="peer_key",
                        before=f"{entry.logical_name} peer key {entry.peer_public_key[:10]}...",
                        after=f"{updated.logical_name} peer key {updated.peer_public_key[:10]}...",
                        reason="Proton rotated the physical server's peer pubkey",
                    )
                )
                changed = True
            new_pool.append(updated)
            continue

        # Entry is truly unusable — find an unused replacement.
        replacement = next(
            (c for c in candidates if c["logical_id"] not in current_ids),
            None,
        )
        if replacement is None:
            warn = (
                f"Pool entry {entry.logical_name} ({entry.logical_id}) is offline "
                "but no replacement candidate is available; keeping stale entry."
            )
            report.warnings.append(warn)
            report.changes.append(
                PoolChange(
                    index=entry.index,
                    kind="offline_no_replacement",
                    before=entry.logical_name,
                    after=entry.logical_name,
                    reason="no free candidate",
                )
            )
            print(f"Warning: {warn}", file=sys.stderr)
            new_pool.append(entry)
            continue
        current_ids.discard(entry.logical_id)
        current_ids.add(replacement["logical_id"])
        report.changes.append(
            PoolChange(
                index=entry.index,
                kind="replaced",
                before=f"{entry.logical_name} {entry.endpoint_ip}",
                after=f"{replacement['logical_name']} {replacement['endpoint_ip']}",
                reason=f"{entry.logical_name} went offline",
            )
        )
        new_pool.append(
            PoolEntry(
                index=entry.index,
                logical_id=replacement["logical_id"],
                logical_name=replacement["logical_name"],
                country=replacement["country"],
                city=replacement["city"],
                tier=replacement["tier"],
                features=replacement["features"],
                physical_id=replacement["physical_id"],
                endpoint_ip=replacement["endpoint_ip"],
                endpoint_port=replacement["endpoint_port"],
                peer_public_key=replacement["peer_public_key"],
                config_file=entry.config_file,
            )
        )
        changed = True

    lib.pool = new_pool
    report.pool_size = len(new_pool)

    # ---- step 3: re-render configs --------------------------------------
    assert lib.identity is not None
    priv_pem = (paths.root / lib.identity.ed25519_private_pem_path).read_text()
    identity = load_identity(priv_pem)
    render = lib.render or {"mode": "client"}
    mode = render.get("mode", "client")
    wg_address = render.get("wg_address") or lib.identity.wg_address or DEFAULT_WG_ADDRESS
    interface_name = render.get("interface_name", "wg0")
    router_params: RouterParams | None = None
    if mode == "router":
        r = render.get("router", {})
        router_params = RouterParams(
            wan_iface=r["wan_iface"],
            lan_gateway=r["lan_gateway"],
            dns=r.get("dns", "8.8.8.8"),
            persistent_keepalive=int(r.get("persistent_keepalive", 25)),
            mtu=r.get("mtu"),
        )
    dns = render.get("dns", "10.2.0.1" if mode == "client" else "8.8.8.8")
    for entry in lib.pool:
        write_config(
            paths.root / entry.config_file,
            identity.wg_private_key_b64,
            wg_address,
            entry,
            mode=mode,
            router=router_params,
            interface_name=interface_name,
            dns=dns,
        )

    if changed or args.force:
        lib.bump_generated_at()
        lib.save(paths.library_file)

    if changed:
        report.summary_line = f"Library refreshed ({len(lib.pool)} entries)."
    else:
        report.summary_line = "No changes."
    print(report.summary_line)
    return 0


def run(args: argparse.Namespace) -> int:
    paths = ProjectPaths.from_root(args.project_root)
    report = RefreshReport(
        host=current_hostname(),
        library_path=str(paths.library_file),
        started_at=datetime.now(timezone.utc),
    )
    try:
        report.exit_code = _do_refresh(args, report)
    except SystemExit as exc:
        # _load_library_or_die calls sys.exit(1) when library is missing.
        report.exit_code = int(exc.code) if isinstance(exc.code, int) else 1
        if not report.error:
            report.error = "Library not initialised (library.json missing)."
    except Exception as exc:
        report.exit_code = 1
        report.error = f"{type(exc).__name__}: {exc}"
        print(traceback.format_exc(), file=sys.stderr)
    finally:
        report.finished_at = datetime.now(timezone.utc)
        cfg = load_config(paths.notify_config)
        safe_send(cfg, report)
    return report.exit_code


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "refresh",
        help="Rotate cert if near expiry, replace dead servers, re-render configs.",
    )
    p.add_argument(
        "--cert-refresh-days",
        type=int,
        default=30,
        help="Rotate the cert when it expires within this many days (default 30).",
    )
    p.add_argument("--device-name", help="DeviceName to use if the cert is rotated.")
    p.add_argument(
        "--force",
        action="store_true",
        help="Save library.json and re-stamp generated_at even if nothing changed.",
    )
    p.set_defaults(func=run)
