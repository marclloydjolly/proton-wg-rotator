"""Pure helpers for the self-healing Proton app-version logic (no proton dep,
so it is unit-testable without the Proton client installed)."""

from __future__ import annotations

# Proton periodically raises the MINIMUM accepted app version and rejects older
# ones with a message containing one of these.
VERSION_REJECTED_MARKERS = (
    "no longer supported",
    "please update",
)

# A light, idempotent GET used only to test whether an app version is accepted.
VERSION_PROBE_ENDPOINT = "/vpn/v1/logicals"


def ver_tuple(appversion: str) -> tuple[int, ...]:
    """Parse 'linux-vpn@4.19.1' -> (4, 19, 1); () if unparseable."""
    try:
        return tuple(int(x) for x in appversion.split("@", 1)[1].split("."))
    except (ValueError, IndexError):
        return ()


def candidate_versions(current: str, *, minor_span: int = 4, patch_span: int = 8) -> list[str]:
    """Versions to probe when `current` is rejected: higher patches of the same
    minor, then low patches of the next few minors. Proton bumps are small while
    we stay current, so the accepted version is normally within the first few."""
    try:
        prefix, ver = current.split("@", 1)
        major, minor, patch = (int(x) for x in ver.split("."))
    except (ValueError, IndexError):
        return []
    out = [f"{prefix}@{major}.{minor}.{p}" for p in range(patch + 1, patch + 1 + patch_span)]
    for m in range(minor + 1, minor + 1 + minor_span):
        out += [f"{prefix}@{major}.{m}.{p}" for p in range(0, 6)]
    return out
