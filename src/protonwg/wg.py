"""
WireGuard .conf file synthesis.

We share a single [Interface] (identity) across all configs in the pool; only
the [Peer] block changes per server. This mirrors how Proton's issued cert
authorises the whole account tier, not a specific server.

Two render modes:

  - CLIENT mode: vanilla tunnel. Bring up with wg-quick and traffic is routed
    through it by default (AllowedIPs 0.0.0.0/0 with default Table handling).
    Appropriate for most individual machines.

  - ROUTER mode: the box acts as a VPN gateway for the LAN. Table=off so
    wg-quick doesn't manage routes itself; PreUp/PostUp pins a direct route
    to the Proton endpoint via the LAN gateway (so the tunnel's encrypted
    packets can reach the internet), swaps the default route onto wg0,
    enables ip_forward, and installs a MASQUERADE NAT rule for the outgoing
    tunnel. Mirrors Marc's existing /etc/wireguard/wg0.conf.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .library import PoolEntry

DEFAULT_CLIENT_DNS = "10.2.0.1"
DEFAULT_KEEPALIVE = 25


@dataclass(frozen=True)
class RouterParams:
    """Extra values needed for a router-mode .conf."""

    wan_iface: str  # e.g. "enp3s0f0"
    lan_gateway: str  # e.g. "192.168.2.254"
    dns: str = "8.8.8.8"
    persistent_keepalive: int = DEFAULT_KEEPALIVE
    mtu: int | None = None  # e.g. 1380 if Proton keeps fragmenting


def render_client(
    identity_priv_key_b64: str,
    wg_address: str,
    entry: PoolEntry,
    *,
    dns: str = DEFAULT_CLIENT_DNS,
) -> str:
    return (
        "[Interface]\n"
        f"PrivateKey = {identity_priv_key_b64}\n"
        f"Address = {wg_address}\n"
        f"DNS = {dns}\n"
        "\n"
        "[Peer]\n"
        f"# {entry.logical_name} ({entry.city}, {entry.country})\n"
        f"PublicKey = {entry.peer_public_key}\n"
        "AllowedIPs = 0.0.0.0/0\n"
        f"Endpoint = {entry.endpoint_ip}:{entry.endpoint_port}\n"
    )


def render_router(
    identity_priv_key_b64: str,
    wg_address: str,
    entry: PoolEntry,
    router: RouterParams,
    *,
    interface_name: str = "wg0",
) -> str:
    """Render a router-mode config mirroring Marc's existing wg0.conf shape."""
    mtu_line = f"MTU = {router.mtu}\n" if router.mtu is not None else ""
    return (
        "[Interface]\n"
        f"PrivateKey = {identity_priv_key_b64}\n"
        f"Address = {wg_address}\n"
        f"DNS = {router.dns}\n"
        "Table = off\n"
        f"{mtu_line}"
        "\n"
        "# Keep a direct route to the WG endpoint over WAN\n"
        f"PreUp   = ip route add {entry.endpoint_ip} via {router.lan_gateway} dev {router.wan_iface} || true\n"
        f"PostDown= ip route del {entry.endpoint_ip} via {router.lan_gateway} dev {router.wan_iface} || true\n"
        "\n"
        "# Switch default to the VPN; restore on down\n"
        f"PostUp   = ip route replace default dev {interface_name}\n"
        f"PostDown = ip route replace default via {router.lan_gateway}\n"
        "\n"
        "# Enable forwarding + NAT out the VPN\n"
        "PostUp   = sysctl -w net.ipv4.ip_forward=1\n"
        f"PostUp   = iptables -t nat -A POSTROUTING -o {interface_name} -j MASQUERADE\n"
        f"PostDown = iptables -t nat -D POSTROUTING -o {interface_name} -j MASQUERADE\n"
        "\n"
        "[Peer]\n"
        f"# {entry.logical_name} ({entry.city}, {entry.country})\n"
        f"PublicKey = {entry.peer_public_key}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        f"Endpoint = {entry.endpoint_ip}:{entry.endpoint_port}\n"
        f"PersistentKeepalive = {router.persistent_keepalive}\n"
    )


Mode = Literal["client", "router"]


def write_config(
    path: Path,
    identity_priv_key_b64: str,
    wg_address: str,
    entry: PoolEntry,
    *,
    mode: Mode = "client",
    router: RouterParams | None = None,
    interface_name: str = "wg0",
    dns: str = DEFAULT_CLIENT_DNS,
) -> None:
    if mode == "router":
        if router is None:
            raise ValueError("mode='router' requires RouterParams")
        body = render_router(
            identity_priv_key_b64,
            wg_address,
            entry,
            router,
            interface_name=interface_name,
        )
    else:
        body = render_client(identity_priv_key_b64, wg_address, entry, dns=dns)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(body)
    tmp.chmod(0o600)
    tmp.replace(path)
