"""Layout of on-disk artefacts relative to the project root."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProjectPaths:
    root: Path

    @classmethod
    def from_root(cls, root: str | Path) -> "ProjectPaths":
        return cls(Path(root).expanduser().resolve())

    # directories
    @property
    def state_dir(self) -> Path:
        return self.root / "state"

    @property
    def configs_dir(self) -> Path:
        return self.root / "configs"

    # files
    @property
    def session_file(self) -> Path:
        return self.state_dir / "session.json"

    @property
    def library_file(self) -> Path:
        return self.root / "library.json"

    @property
    def ed25519_private_pem(self) -> Path:
        return self.state_dir / "ed25519_priv.pem"

    @property
    def ed25519_public_pem(self) -> Path:
        return self.state_dir / "ed25519_pub.pem"

    @property
    def cert_pem(self) -> Path:
        return self.state_dir / "cert.pem"

    @property
    def notify_config(self) -> Path:
        return self.state_dir / "notify.toml"

    @property
    def hotloop_state(self) -> Path:
        return self.state_dir / "hotloop.json"
