"""
Short-term memory for health-check, so recovery stops thrashing.

Two things live here:

* ``recent_failures`` — logical_id → ISO timestamp of when a recovery to (or
  from) that server last failed its post-swap internet check. Recovery excludes
  these for ``failure_cooldown_minutes`` so we don't keep re-selecting a
  server that scores well on Proton's ranking but doesn't actually pass
  traffic (the UK#380 ping-pong).

* ``swap_events`` — ISO timestamps of recent recovery swaps, used for a
  circuit breaker: if too many swaps happen inside a window, stop swapping and
  alert instead of thrashing the tunnel.

State is written 0644 and chowned back to the project owner (root runs
health-check), matching HotLoopState so the user-run refresh can read it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(iso: str) -> datetime | None:
    try:
        return datetime.fromisoformat(iso)
    except ValueError:
        return None


@dataclass
class HealthMemory:
    version: int = 1
    recent_failures: dict[str, str] = field(default_factory=dict)
    swap_events: list[str] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "HealthMemory":
        if not path.exists():
            return cls()
        try:
            with path.open() as fh:
                d = json.load(fh)
        except (json.JSONDecodeError, OSError):
            return cls()
        return cls(
            version=int(d.get("version", 1)),
            recent_failures=dict(d.get("recent_failures", {})),
            swap_events=list(d.get("swap_events", [])),
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": self.version,
            "recent_failures": self.recent_failures,
            "swap_events": self.swap_events,
        }
        tmp = path.with_suffix(".tmp")
        with tmp.open("w") as fh:
            json.dump(payload, fh, indent=2)
        import os

        os.chmod(tmp, 0o644)
        tmp.replace(path)
        try:
            from ._fsutil import chown_to_parent_owner

            chown_to_parent_owner(path)
        except Exception:
            pass

    # ---- failure memory ---------------------------------------------------

    def mark_failed(self, logical_id: str, now: datetime | None = None) -> None:
        self.recent_failures[logical_id] = (now or _now()).isoformat(timespec="seconds")

    def excluded_ids(self, cooldown_minutes: int, now: datetime | None = None) -> set[str]:
        """Logical IDs that failed within the cooldown; prune older entries."""
        now = now or _now()
        cutoff = now - timedelta(minutes=cooldown_minutes)
        keep: dict[str, str] = {}
        excluded: set[str] = set()
        for lid, iso in self.recent_failures.items():
            ts = _parse(iso)
            if ts and ts >= cutoff:
                keep[lid] = iso
                excluded.add(lid)
        self.recent_failures = keep
        return excluded

    # ---- circuit breaker --------------------------------------------------

    def record_swap(self, now: datetime | None = None) -> None:
        self.swap_events.append((now or _now()).isoformat(timespec="seconds"))
        # Keep the list bounded.
        self.swap_events = self.swap_events[-50:]

    def swaps_in_window(self, window_minutes: int, now: datetime | None = None) -> int:
        now = now or _now()
        cutoff = now - timedelta(minutes=window_minutes)
        count = 0
        for iso in self.swap_events:
            ts = _parse(iso)
            if ts and ts >= cutoff:
                count += 1
        return count
