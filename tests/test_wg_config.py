"""The router config must clamp forwarded TCP MSS to the tunnel MTU, or LAN
clients blackhole oversized packets and forwarded throughput collapses."""
from protonwg.wg import render_router, RouterParams
from protonwg.library import PoolEntry


def _entry():
    return PoolEntry(index=1, logical_id="x", logical_name="UK#1", country="UK",
                     city="London", tier=2, features=0, physical_id="p",
                     endpoint_ip="1.2.3.4", endpoint_port=51820,
                     peer_public_key="pub", config_file="configs/gb-lon-01.conf")


def test_router_config_clamps_mss_default_mtu():
    r = RouterParams(wan_iface="enp3s0f0", lan_gateway="192.168.2.254", dns="9.9.9.9", mtu=None)
    out = render_router("priv", "10.100.0.2/32", _entry(), r)
    # default wg MTU 1420 -> MSS 1380, both directions, each with a matching PostDown
    assert "-o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1380" in out
    assert "-i wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1380" in out
    assert out.count("mangle -A FORWARD") == 2
    assert out.count("mangle -D FORWARD") == 2


def test_mss_follows_explicit_mtu():
    r = RouterParams(wan_iface="enp3s0f0", lan_gateway="192.168.2.254", mtu=1400)
    out = render_router("priv", "10.100.0.2/32", _entry(), r)
    assert "--set-mss 1360" in out  # 1400 - 40
