"""
The hot-loop: decide whether to swap the active wg0 tunnel to a better
pool entry based on live Proton Score/Load data, and execute the swap
with rollback if the new peer fails to handshake.

Runs as root (required for `wg show`, editing `/etc/wireguard/wg0.conf`,
and `systemctl restart wg-quick@wg0`).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .library import PoolEntry

APP_VERSION = "linux-vpn@4.13.1"
USER_AGENT = "ProtonVPN/4.13.1 (Linux; Ubuntu)"

Action = Literal["stay", "swap", "emergency_swap", "bootstrap_swap", "error"]


# ---- config ---------------------------------------------------------------


@dataclass
class Policy:
    min_improvement: float = 0.20  # 20% — fraction, not percentage
    min_interval_minutes: int = 30
    dead_handshake_seconds: int = 300
    rollback_wait_seconds: int = 15
    handshake_freshness_seconds: int = 30
    interface: str = "wg0"
    wg_conf_path: Path = Path("/etc/wireguard/wg0.conf")


# ---- live metrics ---------------------------------------------------------


@dataclass
class LoadMetrics:
    score: float
    load: int
    status: int

    @classmethod
    def from_loads_entry(cls, entry: dict) -> "LoadMetrics":
        return cls(
            score=float(entry.get("Score", 1e6)),
            load=int(entry.get("Load", 100)),
            status=int(entry.get("Status", 0)),
        )


@dataclass
class RankedCandidate:
    entry: PoolEntry
    metrics: LoadMetrics
    is_current: bool = False


# ---- state ----------------------------------------------------------------


@dataclass
class HotLoopState:
    version: int = 1
    last_swap_at: str | None = None
    last_swap_target_logical: str | None = None
    last_swap_result: str | None = None  # ok | rolled_back | failed
    swap_count_total: int = 0

    @classmethod
    def load(cls, path: Path) -> "HotLoopState":
        if not path.exists():
            return cls()
        with path.open() as fh:
            d = json.load(fh)
        return cls(
            version=int(d.get("version", 1)),
            last_swap_at=d.get("last_swap_at"),
            last_swap_target_logical=d.get("last_swap_target_logical"),
            last_swap_result=d.get("last_swap_result"),
            swap_count_total=int(d.get("swap_count_total", 0)),
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": self.version,
            "last_swap_at": self.last_swap_at,
            "last_swap_target_logical": self.last_swap_target_logical,
            "last_swap_result": self.last_swap_result,
            "swap_count_total": self.swap_count_total,
        }
        tmp = path.with_suffix(".tmp")
        with tmp.open("w") as fh:
            json.dump(payload, fh, indent=2)
        os.chmod(tmp, 0o644)
        tmp.replace(path)
        # See _fsutil: prevent root-owned state files after root writes.
        from ._fsutil import chown_to_parent_owner
        chown_to_parent_owner(path)


# ---- decision -------------------------------------------------------------


@dataclass
class Decision:
    action: Action
    reason: str
    target: PoolEntry | None = None
    target_metrics: LoadMetrics | None = None
    current_entry: PoolEntry | None = None
    current_metrics: LoadMetrics | None = None
    current_handshake_age_s: int | None = None
    improvement: float | None = None
    ranked: list[RankedCandidate] = field(default_factory=list)


def rank_pool(
    pool: list[PoolEntry],
    loads: dict[str, dict],
    current_pubkey: str | None,
) -> list[RankedCandidate]:
    ranked: list[RankedCandidate] = []
    for entry in pool:
        ld = loads.get(entry.logical_id)
        if ld is None:
            continue
        m = LoadMetrics.from_loads_entry(ld)
        ranked.append(
            RankedCandidate(
                entry=entry,
                metrics=m,
                is_current=(current_pubkey == entry.peer_public_key),
            )
        )
    ranked.sort(key=lambda c: c.metrics.score)
    return ranked


def decide(
    pool: list[PoolEntry],
    loads: dict[str, dict],
    current_pubkey: str | None,
    current_handshake_age_s: int | None,
    state: HotLoopState,
    policy: Policy,
    now: datetime | None = None,
) -> Decision:
    now = now or datetime.now(timezone.utc)
    ranked = rank_pool(pool, loads, current_pubkey)
    live = [c for c in ranked if c.metrics.status == 1]

    if not live:
        return Decision(
            action="error",
            reason="No live candidates in pool (all Status != 1).",
            ranked=ranked,
        )

    best = live[0]
    current = next((c for c in ranked if c.is_current), None)

    # Bootstrap: the interface isn't on a pool peer (e.g. still on the original
    # hand-downloaded wg0.conf). Swap to best candidate unconditionally.
    if current is None:
        return Decision(
            action="bootstrap_swap",
            reason=(
                "Current tunnel peer is not in the managed pool; swapping to "
                f"best candidate {best.entry.logical_name} "
                f"(score {best.metrics.score:.2f})."
            ),
            target=best.entry,
            target_metrics=best.metrics,
            current_handshake_age_s=current_handshake_age_s,
            ranked=ranked,
        )

    # Emergency: current logical is offline in live loads.
    if current.metrics.status != 1:
        return Decision(
            action="emergency_swap",
            reason=(
                f"Current server {current.entry.logical_name} is offline "
                f"(Status={current.metrics.status}); swapping to "
                f"{best.entry.logical_name}."
            ),
            target=best.entry,
            target_metrics=best.metrics,
            current_entry=current.entry,
            current_metrics=current.metrics,
            current_handshake_age_s=current_handshake_age_s,
            ranked=ranked,
        )

    # Emergency: stale handshake.
    if (
        current_handshake_age_s is not None
        and current_handshake_age_s > policy.dead_handshake_seconds
    ):
        return Decision(
            action="emergency_swap",
            reason=(
                f"Current handshake age {current_handshake_age_s}s exceeds "
                f"{policy.dead_handshake_seconds}s threshold; swapping to "
                f"{best.entry.logical_name}."
            ),
            target=best.entry,
            target_metrics=best.metrics,
            current_entry=current.entry,
            current_metrics=current.metrics,
            current_handshake_age_s=current_handshake_age_s,
            ranked=ranked,
        )

    # Same server is already best.
    if best.entry.logical_id == current.entry.logical_id:
        return Decision(
            action="stay",
            reason=(
                f"Already on the best candidate ({current.entry.logical_name}, "
                f"score {current.metrics.score:.2f}, load {current.metrics.load}%)."
            ),
            current_entry=current.entry,
            current_metrics=current.metrics,
            current_handshake_age_s=current_handshake_age_s,
            ranked=ranked,
        )

    # Score comparison.
    improvement = 0.0
    if current.metrics.score > 0:
        improvement = (current.metrics.score - best.metrics.score) / current.metrics.score

    if improvement < policy.min_improvement:
        return Decision(
            action="stay",
            reason=(
                f"Potential swap to {best.entry.logical_name} "
                f"(score {best.metrics.score:.2f}) would improve current "
                f"{current.entry.logical_name} (score {current.metrics.score:.2f}) "
                f"by only {improvement:.1%}, below {policy.min_improvement:.0%} threshold."
            ),
            target=best.entry,
            target_metrics=best.metrics,
            current_entry=current.entry,
            current_metrics=current.metrics,
            current_handshake_age_s=current_handshake_age_s,
            improvement=improvement,
            ranked=ranked,
        )

    # Cooldown.
    if state.last_swap_at:
        try:
            last = datetime.fromisoformat(state.last_swap_at)
            elapsed_min = (now - last).total_seconds() / 60
            if elapsed_min < policy.min_interval_minutes:
                return Decision(
                    action="stay",
                    reason=(
                        f"Swap to {best.entry.logical_name} is wanted "
                        f"({improvement:.1%} better) but last swap was "
                        f"{elapsed_min:.0f}m ago, cooldown {policy.min_interval_minutes}m "
                        "not elapsed."
                    ),
                    target=best.entry,
                    target_metrics=best.metrics,
                    current_entry=current.entry,
                    current_metrics=current.metrics,
                    current_handshake_age_s=current_handshake_age_s,
                    improvement=improvement,
                    ranked=ranked,
                )
        except ValueError:
            pass

    return Decision(
        action="swap",
        reason=(
            f"{best.entry.logical_name} scores {best.metrics.score:.2f} "
            f"vs current {current.entry.logical_name} {current.metrics.score:.2f} "
            f"({improvement:.1%} improvement, cooldown clear)."
        ),
        target=best.entry,
        target_metrics=best.metrics,
        current_entry=current.entry,
        current_metrics=current.metrics,
        current_handshake_age_s=current_handshake_age_s,
        improvement=improvement,
        ranked=ranked,
    )


# ---- probes ---------------------------------------------------------------


def fetch_loads(client) -> dict[str, dict]:
    """
    Return live per-logical metrics as ``{logical_id: {"Score", "Load", "Status"}}``.

    Sourced from the authenticated ``/vpn/v1/logicals`` endpoint (the
    unauthenticated ``/vpn/loads`` endpoint was deprecated by Proton and
    now returns an empty list for all app-version strings — see git
    commit history for the discovery).

    Requires an active ``ProtonClient`` with a loaded session. All callers
    (swap-check, health-check, apiserver) run as root, so they can read
    the user-owned ``state/session.json`` regardless of its 0600 perms.
    """
    logicals = client.get_logicals()
    out: dict[str, dict] = {}
    for s in logicals:
        sid = s.get("ID")
        if sid is None:
            continue
        out[sid] = {
            "Score": s.get("Score", 1e6),
            "Load": s.get("Load", 100),
            "Status": s.get("Status", 0),
        }
    return out


def _wg_cmd(args: list[str]) -> list[str]:
    """Prepend `sudo -n` when not root so user-level callers can still read wg state."""
    if os.geteuid() == 0:
        return ["wg"] + args
    return ["sudo", "-n", "wg"] + args


def get_current_peer_pubkey(iface: str) -> str | None:
    try:
        r = subprocess.run(
            _wg_cmd(["show", iface, "dump"]),
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return None
    lines = r.stdout.strip().split("\n")
    if len(lines) < 2:
        return None
    # Line 0 = interface, line 1+ = peers. First peer's pubkey is field 0.
    return lines[1].split("\t")[0]


def get_handshake_age_seconds(iface: str) -> int | None:
    try:
        r = subprocess.run(
            _wg_cmd(["show", iface, "latest-handshakes"]),
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return None
    lines = [ln for ln in r.stdout.strip().split("\n") if ln]
    if not lines:
        return None
    parts = lines[0].split("\t")
    if len(parts) < 2:
        return None
    try:
        ts = int(parts[1])
    except ValueError:
        return None
    if ts == 0:
        return None
    return int(time.time()) - ts


@dataclass
class TunnelSnapshot:
    """One-shot view of the current wg interface, parsed from `wg show ... dump`."""

    peer_pubkey: str | None
    endpoint: str | None  # "ip:port" or None if peer never contacted
    endpoint_ip: str | None
    endpoint_port: int | None
    handshake_age_s: int | None
    rx_bytes: int | None
    tx_bytes: int | None
    keepalive_s: int | None

    @classmethod
    def empty(cls) -> "TunnelSnapshot":
        return cls(None, None, None, None, None, None, None, None)


def get_tunnel_snapshot(iface: str) -> TunnelSnapshot:
    """Parse `wg show <iface> dump` once and return everything the API surfaces."""
    try:
        r = subprocess.run(
            _wg_cmd(["show", iface, "dump"]),
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return TunnelSnapshot.empty()
    lines = [ln for ln in r.stdout.strip().split("\n") if ln]
    if len(lines) < 2:
        return TunnelSnapshot.empty()
    # Peer line fields, tab-separated:
    #   0=pubkey  1=psk  2=endpoint  3=allowed-ips  4=latest-handshake-unix
    #   5=rx-bytes  6=tx-bytes  7=keepalive-sec
    fields = lines[1].split("\t")
    if len(fields) < 8:
        return TunnelSnapshot.empty()

    pubkey = fields[0] or None
    endpoint_raw = fields[2] if fields[2] and fields[2] != "(none)" else None
    endpoint_ip: str | None = None
    endpoint_port: int | None = None
    if endpoint_raw and ":" in endpoint_raw:
        # IPv4 "ip:port" or IPv6 "[::1]:port"; only IPv4 supported by pool today.
        try:
            ip_part, port_part = endpoint_raw.rsplit(":", 1)
            endpoint_ip = ip_part.strip("[]")
            endpoint_port = int(port_part)
        except (ValueError, IndexError):
            pass

    def _maybe_int(v: str) -> int | None:
        try:
            return int(v)
        except ValueError:
            return None

    hs_unix = _maybe_int(fields[4])
    hs_age = int(time.time()) - hs_unix if hs_unix and hs_unix > 0 else None

    return TunnelSnapshot(
        peer_pubkey=pubkey,
        endpoint=endpoint_raw,
        endpoint_ip=endpoint_ip,
        endpoint_port=endpoint_port,
        handshake_age_s=hs_age,
        rx_bytes=_maybe_int(fields[5]),
        tx_bytes=_maybe_int(fields[6]),
        keepalive_s=_maybe_int(fields[7]),
    )


# ---- execution ------------------------------------------------------------


@dataclass
class SwapResult:
    ok: bool
    rolled_back: bool
    error: str | None
    duration_ms: int
    handshake_age_after_s: int | None


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)


def execute_swap(
    target: PoolEntry,
    project_root: Path,
    policy: Policy,
) -> SwapResult:
    start = time.time()
    source = project_root / target.config_file
    if not source.exists():
        return SwapResult(
            ok=False,
            rolled_back=False,
            error=f"Source config missing: {source}",
            duration_ms=0,
            handshake_age_after_s=None,
        )

    rollback_path = policy.wg_conf_path.with_suffix(".conf.rollback")

    # 1. Snapshot current
    if policy.wg_conf_path.exists():
        shutil.copy2(policy.wg_conf_path, rollback_path)
        have_rollback = True
    else:
        have_rollback = False

    # 2. Install new
    try:
        shutil.copy2(source, policy.wg_conf_path)
        os.chmod(policy.wg_conf_path, 0o600)
    except Exception as exc:
        return SwapResult(
            ok=False,
            rolled_back=False,
            error=f"Install failed: {exc}",
            duration_ms=int((time.time() - start) * 1000),
            handshake_age_after_s=None,
        )

    # 3. Restart
    r = _run(["systemctl", "restart", f"wg-quick@{policy.interface}"])
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "").strip()
        if have_rollback:
            shutil.copy2(rollback_path, policy.wg_conf_path)
            _run(["systemctl", "restart", f"wg-quick@{policy.interface}"])
            return SwapResult(
                ok=False,
                rolled_back=True,
                error=f"Restart failed, rolled back. stderr={err}",
                duration_ms=int((time.time() - start) * 1000),
                handshake_age_after_s=None,
            )
        return SwapResult(
            ok=False,
            rolled_back=False,
            error=f"Restart failed, no rollback available. stderr={err}",
            duration_ms=int((time.time() - start) * 1000),
            handshake_age_after_s=None,
        )

    # 4. Wait for handshake
    age: int | None = None
    for _ in range(policy.rollback_wait_seconds):
        time.sleep(1)
        age = get_handshake_age_seconds(policy.interface)
        if age is not None and age <= policy.handshake_freshness_seconds:
            return SwapResult(
                ok=True,
                rolled_back=False,
                error=None,
                duration_ms=int((time.time() - start) * 1000),
                handshake_age_after_s=age,
            )

    # 5. No handshake -> rollback
    if have_rollback:
        shutil.copy2(rollback_path, policy.wg_conf_path)
        _run(["systemctl", "restart", f"wg-quick@{policy.interface}"])
        return SwapResult(
            ok=False,
            rolled_back=True,
            error=(
                f"No handshake within {policy.rollback_wait_seconds}s "
                f"(last age {age}); rolled back."
            ),
            duration_ms=int((time.time() - start) * 1000),
            handshake_age_after_s=age,
        )
    return SwapResult(
        ok=False,
        rolled_back=False,
        error=f"No handshake within {policy.rollback_wait_seconds}s, no rollback available.",
        duration_ms=int((time.time() - start) * 1000),
        handshake_age_after_s=age,
    )
