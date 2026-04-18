"""
`protonwg rebuild-pool` — re-select the pool from fresh logicals, keeping
the existing identity + certificate.

Use this when you want to change filters, take advantage of a selection
algorithm update, or simply re-pick because the server landscape has shifted.
Unlike `init --force`, this does NOT register a new cert, so it won't
accumulate stale entries in the Proton dashboard.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ..api import ProtonAPIError, ProtonClient
from ..crypto import load_identity
from ..library import DEFAULT_WG_ADDRESS, Library, PoolEntry
from ..paths import ProjectPaths
from ..selection import select_pool
from ..wg import RouterParams, write_config


def run(args: argparse.Namespace) -> int:
    paths = ProjectPaths.from_root(args.project_root)
    if not paths.library_file.exists():
        print(
            f"{paths.library_file} does not exist. Run `protonwg init` first.",
            file=sys.stderr,
        )
        return 1
    lib = Library.load(paths.library_file)
    if lib.identity is None:
        print("Library has no identity; cannot rebuild pool.", file=sys.stderr)
        return 1

    client = ProtonClient(paths.session_file)
    if not client.is_logged_in():
        print("Not logged in. Run `protonwg login` first.", file=sys.stderr)
        return 1

    # Use either the flags supplied or the original filters stored in library.
    filters = lib.filters or {}
    country = args.country or filters.get("country", "UK")
    city = args.city or filters.get("city", "London")
    max_tier = args.max_tier if args.max_tier is not None else int(filters.get("max_tier", 2))
    size = args.size if args.size is not None else len(lib.pool) or 15

    try:
        logicals = client.get_logicals()
    except ProtonAPIError as exc:
        print(f"Failed to list logicals: {exc}", file=sys.stderr)
        return 1

    chosen = select_pool(
        logicals,
        country=country,
        city=city,
        max_tier=max_tier,
        size=size,
        prefer_distinct_ips=not args.no_distinct_ips,
    )
    if not chosen:
        print(
            f"No servers matched filters country={country} city={city} "
            f"max_tier={max_tier}.",
            file=sys.stderr,
        )
        return 1

    # Re-render using the render params stored in library.json.
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

    # Drop the old .conf files whose indices we won't reuse.
    for entry in lib.pool:
        p = paths.root / entry.config_file
        if p.exists():
            p.unlink()

    pool: list[PoolEntry] = []
    for i, server in enumerate(chosen, start=1):
        config_name = f"gb-lon-{i:02d}.conf"
        entry = PoolEntry(
            index=i,
            logical_id=server["logical_id"],
            logical_name=server["logical_name"],
            country=server["country"],
            city=server["city"],
            tier=server["tier"],
            features=server["features"],
            physical_id=server["physical_id"],
            endpoint_ip=server["endpoint_ip"],
            endpoint_port=server["endpoint_port"],
            peer_public_key=server["peer_public_key"],
            config_file=f"configs/{config_name}",
        )
        write_config(
            paths.configs_dir / config_name,
            identity.wg_private_key_b64,
            wg_address,
            entry,
            mode=mode,
            router=router_params,
            interface_name=interface_name,
            dns=dns,
        )
        pool.append(entry)

    lib.pool = pool
    lib.filters = {"country": country, "city": city, "max_tier": max_tier}
    lib.bump_generated_at()
    lib.save(paths.library_file)

    distinct_ips = len({e.endpoint_ip for e in pool})
    print(
        f"Rebuilt pool: {len(pool)} entries across {distinct_ips} "
        f"distinct endpoint IP{'s' if distinct_ips != 1 else ''}. "
        f"Cert {lib.identity.cert_serial} unchanged."
    )
    return 0


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "rebuild-pool",
        help="Re-select the pool from fresh logicals without touching the cert.",
    )
    p.add_argument("--country", help="Override country filter.")
    p.add_argument("--city", help="Override city filter.")
    p.add_argument("--max-tier", type=int, help="Override tier filter.")
    p.add_argument("--size", type=int, help="Override pool size.")
    p.add_argument(
        "--no-distinct-ips",
        action="store_true",
        help="Disable IP-diversity preference (fall back to pure Score ranking).",
    )
    p.set_defaults(func=run)
