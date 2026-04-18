"""`protonwg init` — generate identity, register cert, build initial pool + configs."""

from __future__ import annotations

import argparse
import socket
import sys
import time
from datetime import datetime, timezone

from ..api import ProtonAPIError, ProtonClient
from ..crypto import generate_identity
from ..library import DEFAULT_WG_ADDRESS, Identity, Library, PoolEntry
from ..paths import ProjectPaths
from ..selection import select_pool
from ..wg import RouterParams, write_config


def run(args: argparse.Namespace) -> int:
    paths = ProjectPaths.from_root(args.project_root)

    if paths.library_file.exists() and not args.force:
        print(
            f"{paths.library_file} already exists. Use --force to rebuild "
            "(existing cert will be replaced).",
            file=sys.stderr,
        )
        return 1

    client = ProtonClient(paths.session_file)
    if not client.is_logged_in():
        print("Not logged in. Run `protonwg login` first.", file=sys.stderr)
        return 1

    # 1. Fresh identity.
    identity = generate_identity()
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.ed25519_private_pem.write_text(identity.ed25519_private_pem)
    paths.ed25519_private_pem.chmod(0o600)
    paths.ed25519_public_pem.write_text(identity.ed25519_public_pem)

    # 2. Register cert on the account.
    device_name = args.device_name or f"protonwg-{socket.gethostname()}-{int(time.time())}"
    try:
        cert = client.register_certificate(
            identity.ed25519_public_pem, device_name=device_name
        )
    except ProtonAPIError as exc:
        print(f"Certificate registration failed: {exc}", file=sys.stderr)
        return 1
    paths.cert_pem.write_text(cert.certificate_pem)
    paths.cert_pem.chmod(0o600)

    # 3. Fetch + filter logicals.
    try:
        logicals = client.get_logicals()
    except ProtonAPIError as exc:
        print(f"Failed to list logicals: {exc}", file=sys.stderr)
        return 1

    chosen = select_pool(
        logicals,
        country=args.country,
        city=args.city,
        max_tier=args.max_tier,
        size=args.size,
    )
    if not chosen:
        print(
            f"No servers matched filters country={args.country} city={args.city} "
            f"max_tier={args.max_tier}. Check /vpn/v1/logicals contents.",
            file=sys.stderr,
        )
        return 1
    if len(chosen) < args.size:
        print(
            f"Warning: only {len(chosen)} servers matched (requested {args.size}). "
            "Consider relaxing filters.",
            file=sys.stderr,
        )

    # 4. Build render params (client vs router).
    if args.router_mode:
        missing = [
            name
            for name, val in (
                ("--wan-iface", args.wan_iface),
                ("--lan-gateway", args.lan_gateway),
            )
            if not val
        ]
        if missing:
            print(
                f"--router-mode requires {', '.join(missing)}.",
                file=sys.stderr,
            )
            return 1
        router = RouterParams(
            wan_iface=args.wan_iface,
            lan_gateway=args.lan_gateway,
            dns=args.dns or "8.8.8.8",
            persistent_keepalive=args.keepalive,
            mtu=args.mtu,
        )
        render_params: dict[str, object] = {
            "mode": "router",
            "wg_address": args.wg_address,
            "interface_name": args.interface_name,
            "router": {
                "wan_iface": router.wan_iface,
                "lan_gateway": router.lan_gateway,
                "dns": router.dns,
                "persistent_keepalive": router.persistent_keepalive,
                "mtu": router.mtu,
            },
        }
    else:
        router = None
        render_params = {
            "mode": "client",
            "wg_address": args.wg_address,
            "dns": args.dns or "10.2.0.1",
        }

    # 5. Build library + write configs.
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
            args.wg_address,
            entry,
            mode="router" if args.router_mode else "client",
            router=router,
            interface_name=args.interface_name,
            dns=args.dns or ("8.8.8.8" if args.router_mode else "10.2.0.1"),
        )
        pool.append(entry)

    lib = Library(
        identity=Identity(
            ed25519_private_pem_path=str(paths.ed25519_private_pem.relative_to(paths.root)),
            ed25519_public_pem_path=str(paths.ed25519_public_pem.relative_to(paths.root)),
            cert_pem_path=str(paths.cert_pem.relative_to(paths.root)),
            cert_serial=cert.serial_number,
            cert_expires_at=datetime.fromtimestamp(
                cert.expiration_time, tz=timezone.utc
            ).isoformat(timespec="seconds"),
            wg_address=args.wg_address,
        ),
        filters={"country": args.country, "city": args.city, "max_tier": args.max_tier},
        render=render_params,
        pool=pool,
    )
    lib.save(paths.library_file)

    print(
        f"Built pool of {len(pool)} configs in {paths.configs_dir}. "
        f"Cert {cert.serial_number} expires {lib.identity.cert_expires_at}."
    )
    return 0


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser("init", help="Build the initial config pool.")
    p.add_argument(
        "--country",
        default="UK",
        help="ExitCountry filter (default UK). Note Proton uses 'UK' not ISO 'GB'.",
    )
    p.add_argument("--city", default="London", help="City filter (default London).")
    p.add_argument(
        "--max-tier",
        type=int,
        default=2,
        help="Max server tier (0=Free, 2=Plus, 3=PM). Default 2.",
    )
    p.add_argument("--size", type=int, default=15, help="Target pool size (default 15).")
    p.add_argument("--device-name", help="DeviceName sent to Proton when registering cert.")
    p.add_argument(
        "--force",
        action="store_true",
        help="Rebuild even if library.json exists (replaces identity & cert).",
    )
    # Render-mode options.
    p.add_argument(
        "--router-mode",
        action="store_true",
        help="Emit router-style configs (Table=off, PreUp/PostUp/PostDown, MASQUERADE). "
        "Requires --wan-iface and --lan-gateway.",
    )
    p.add_argument(
        "--wg-address",
        default=DEFAULT_WG_ADDRESS,
        help=f"Address= line in [Interface] (default {DEFAULT_WG_ADDRESS}).",
    )
    p.add_argument(
        "--interface-name",
        default="wg0",
        help="Interface name used in PostUp/PostDown rules (router mode only, default wg0).",
    )
    p.add_argument("--wan-iface", help="WAN interface, e.g. enp3s0f0 (router mode).")
    p.add_argument("--lan-gateway", help="LAN gateway IP, e.g. 192.168.2.254 (router mode).")
    p.add_argument("--dns", help="DNS= line (default 8.8.8.8 in router, 10.2.0.1 in client).")
    p.add_argument(
        "--keepalive",
        type=int,
        default=25,
        help="PersistentKeepalive= seconds (router mode, default 25).",
    )
    p.add_argument("--mtu", type=int, help="Optional MTU= line (e.g. 1380).")
    p.set_defaults(func=run)
