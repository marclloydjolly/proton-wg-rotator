"""
The on-disk JSON library: one manifest file tying pool entries to config files.

Schema (see library.json after `protonwg init`):

    {
      "version": 1,
      "generated_at": "<iso8601>",
      "identity": {
        "ed25519_private_pem_path": "state/ed25519_priv.pem",
        "ed25519_public_pem_path":  "state/ed25519_pub.pem",
        "cert_pem_path":            "state/cert.pem",
        "cert_serial":              "...",
        "cert_expires_at":          "<iso8601>",
        "wg_address":               "10.2.0.2/32"
      },
      "filters": {"country": "GB", "city": "London", "max_tier": 2},
      "pool": [
        {
          "index": 1,
          "logical_id": "...", "logical_name": "GB#42",
          "country": "GB", "city": "London", "tier": 2,
          "features": 0,
          "physical_id": "...", "endpoint_ip": "185.x.x.x",
          "endpoint_port": 51820, "peer_public_key": "base64...",
          "config_file": "configs/gb-lon-01.conf"
        },
        ...
      ]
    }
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
DEFAULT_WG_ADDRESS = "10.2.0.2/32"


@dataclass
class Identity:
    ed25519_private_pem_path: str
    ed25519_public_pem_path: str
    cert_pem_path: str
    cert_serial: str
    cert_expires_at: str
    wg_address: str = DEFAULT_WG_ADDRESS


@dataclass
class PoolEntry:
    index: int
    logical_id: str
    logical_name: str
    country: str
    city: str
    tier: int
    features: int
    physical_id: str
    endpoint_ip: str
    endpoint_port: int
    peer_public_key: str
    config_file: str


@dataclass
class Library:
    version: int = SCHEMA_VERSION
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    identity: Identity | None = None
    filters: dict[str, Any] = field(default_factory=dict)
    # Render mode + parameters, stashed so refresh() keeps emitting the same
    # shape without the user re-supplying flags on every run.
    render: dict[str, Any] = field(default_factory=dict)
    pool: list[PoolEntry] = field(default_factory=list)

    # ---- (de)serialisation -------------------------------------------------

    @classmethod
    def load(cls, path: Path) -> "Library":
        with path.open("r") as fh:
            data = json.load(fh)
        identity_data = data.get("identity")
        return cls(
            version=data.get("version", SCHEMA_VERSION),
            generated_at=data.get("generated_at", ""),
            identity=Identity(**identity_data) if identity_data else None,
            filters=data.get("filters", {}),
            render=data.get("render", {}),
            pool=[PoolEntry(**entry) for entry in data.get("pool", [])],
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": self.version,
            "generated_at": self.generated_at,
            "identity": asdict(self.identity) if self.identity else None,
            "filters": self.filters,
            "render": self.render,
            "pool": [asdict(entry) for entry in self.pool],
        }
        tmp = path.with_suffix(".tmp")
        with tmp.open("w") as fh:
            json.dump(payload, fh, indent=2)
        tmp.replace(path)
        # See _fsutil: prevent root-owned library files after root writes.
        from ._fsutil import chown_to_parent_owner
        chown_to_parent_owner(path)

    # ---- lookups -----------------------------------------------------------

    def by_logical_id(self) -> dict[str, PoolEntry]:
        return {entry.logical_id: entry for entry in self.pool}

    def bump_generated_at(self) -> None:
        self.generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
