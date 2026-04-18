"""
Pool selection: turn a raw /vpn/v1/logicals response into a flat list of
normalised candidates for the pool, filtered and ranked.

Feature bits (from ProtonVPN/python-proton-vpn-api-core):
    1 = Secure Core
    2 = Tor
    4 = P2P
    8 = Streaming
   16 = IPv6
We exclude Secure Core and Tor by default — they're distinct infrastructure and
not what "standard VPN" means. P2P / streaming / IPv6 bits are fine either way.
"""

from __future__ import annotations

from typing import Any, Iterable

FEATURE_SECURE_CORE = 1
FEATURE_TOR = 2
EXCLUDE_MASK = FEATURE_SECURE_CORE | FEATURE_TOR

STATUS_ONLINE = 1
DEFAULT_WG_PORT = 51820


def logical_passes_filter(
    logical: dict[str, Any],
    *,
    country: str,
    city: str,
    max_tier: int,
) -> bool:
    """Shared predicate: is this logical eligible for the pool given filters?"""
    if logical.get("Status") != STATUS_ONLINE:
        return False
    if logical.get("ExitCountry") != country:
        return False
    if city and (logical.get("City") or "").lower() != city.lower():
        return False
    if int(logical.get("Tier", 0)) > max_tier:
        return False
    if int(logical.get("Features", 0)) & EXCLUDE_MASK:
        return False
    return True


def normalise_logical(logical: dict[str, Any]) -> dict[str, Any] | None:
    """Public alias for the internal normaliser."""
    return _normalise(logical)


def _pick_physical(physicals: list[dict[str, Any]]) -> dict[str, Any] | None:
    active = [p for p in physicals if p.get("Status") == STATUS_ONLINE]
    if not active:
        return None
    # Stable: lowest ExitIP wins. Keeps the pool deterministic run to run.
    active.sort(key=lambda p: p.get("ExitIP") or "")
    return active[0]


def _normalise(logical: dict[str, Any]) -> dict[str, Any] | None:
    physical = _pick_physical(logical.get("Servers", []))
    if physical is None:
        return None
    peer_key = physical.get("X25519PublicKey")
    endpoint_ip = physical.get("ExitIP")
    if not peer_key or not endpoint_ip:
        return None
    return {
        "logical_id": logical["ID"],
        "logical_name": logical.get("Name", ""),
        "country": logical.get("ExitCountry", ""),
        "city": logical.get("City", "") or "",
        "tier": int(logical.get("Tier", 0)),
        "features": int(logical.get("Features", 0)),
        "score": float(logical.get("Score", 0.0)),
        "load": int(logical.get("Load", 0)),
        "physical_id": physical.get("ID", ""),
        "endpoint_ip": endpoint_ip,
        "endpoint_port": DEFAULT_WG_PORT,
        "peer_public_key": peer_key,
    }


def select_pool(
    logicals: Iterable[dict[str, Any]],
    *,
    country: str,
    city: str,
    max_tier: int,
    size: int,
    prefer_distinct_ips: bool = True,
) -> list[dict[str, Any]]:
    """
    Pick `size` logicals to form the pool.

    Strategy (with ``prefer_distinct_ips=True``, the default):

      1. Filter by country/city/tier/status/features.
      2. Sort candidates by Proton's Score ascending (lower is better).
      3. Walk the sorted list keeping the *first* (=best-scoring) logical
         for each distinct endpoint IP. This maximises physical-gateway
         diversity rather than cramming 15 logicals onto one box.
      4. If fewer distinct IPs than `size`, top up with the next-best
         logicals (IPs will repeat). Never shrink the pool silently.
      5. Display-sort by name for stable output across runs.
    """
    candidates: list[dict[str, Any]] = []
    for logical in logicals:
        if logical.get("Status") != STATUS_ONLINE:
            continue
        if logical.get("ExitCountry") != country:
            continue
        if city and (logical.get("City") or "").lower() != city.lower():
            continue
        if int(logical.get("Tier", 0)) > max_tier:
            continue
        if int(logical.get("Features", 0)) & EXCLUDE_MASK:
            continue
        normalised = _normalise(logical)
        if normalised is not None:
            candidates.append(normalised)

    # Rank by current Score ascending (Proton's own "best server" signal).
    candidates.sort(key=lambda c: c["score"])

    if not prefer_distinct_ips:
        chosen = candidates[:size]
    else:
        # Pass 1: best logical per distinct endpoint IP.
        chosen: list[dict[str, Any]] = []
        seen_ips: set[str] = set()
        leftovers: list[dict[str, Any]] = []
        for c in candidates:
            if c["endpoint_ip"] not in seen_ips:
                chosen.append(c)
                seen_ips.add(c["endpoint_ip"])
                if len(chosen) >= size:
                    break
            else:
                leftovers.append(c)
        # Pass 2: top up with next-best duplicates if we ran out of IPs.
        if len(chosen) < size:
            for c in leftovers:
                chosen.append(c)
                if len(chosen) >= size:
                    break

    # Display order: stable by name.
    chosen.sort(key=lambda c: c["logical_name"])
    return chosen
