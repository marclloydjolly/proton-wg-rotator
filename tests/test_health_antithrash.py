"""Tests for the anti-thrash health-check logic: failure memory, circuit
breaker, and recovery-target exclusion in decide()."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from protonwg.health_memory import HealthMemory
from protonwg.hotloop import HotLoopState, Policy, decide
from protonwg.library import PoolEntry


def _entry(i: int) -> PoolEntry:
    return PoolEntry(
        index=i,
        logical_id=f"lid{i}",
        logical_name=f"UK#{i}",
        country="UK",
        city="London",
        tier=2,
        features=0,
        physical_id=f"pid{i}",
        endpoint_ip=f"10.0.0.{i}",
        endpoint_port=51820,
        peer_public_key=f"pub{i}",
        config_file=f"configs/gb-lon-{i:02d}.conf",
    )


def _loads(scores: dict[str, float]) -> dict[str, dict]:
    return {lid: {"Score": s, "Load": 30, "Status": 1} for lid, s in scores.items()}


# ---- HealthMemory: failure cooldown --------------------------------------


def test_failed_server_excluded_then_expires(tmp_path):
    mem = HealthMemory()
    now = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
    mem.mark_failed("lid1", now=now)

    # Within cooldown → excluded.
    assert "lid1" in mem.excluded_ids(20, now=now + timedelta(minutes=5))
    # After cooldown → gone (and pruned).
    assert mem.excluded_ids(20, now=now + timedelta(minutes=25)) == set()
    assert "lid1" not in mem.recent_failures


def test_memory_roundtrips_to_disk(tmp_path):
    path = tmp_path / "health.json"
    mem = HealthMemory()
    mem.mark_failed("lidX")
    mem.record_swap()
    mem.save(path)
    again = HealthMemory.load(path)
    assert "lidX" in again.recent_failures
    assert len(again.swap_events) == 1


# ---- HealthMemory: circuit breaker ---------------------------------------


def test_circuit_breaker_counts_only_recent_swaps():
    mem = HealthMemory()
    now = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
    for m in (2, 5, 9, 40):  # three within 30m, one outside
        mem.swap_events.append((now - timedelta(minutes=m)).isoformat(timespec="seconds"))
    assert mem.swaps_in_window(30, now=now) == 3


# ---- decide(): exclusion -------------------------------------------------


def test_recovery_excludes_failed_and_picks_next_best():
    pool = [_entry(1), _entry(2), _entry(3)]
    loads = _loads({"lid1": 1.50, "lid2": 1.60, "lid3": 1.70})  # lid1 best
    # wg0 down (current_pubkey=None) → bootstrap; exclude lid1 (just failed).
    d = decide(pool, loads, None, None, HotLoopState(), Policy(),
               exclude_logical_ids={"lid1"})
    assert d.action == "bootstrap_swap"
    assert d.target.logical_id == "lid2"  # next best, not the excluded best


def test_exclusion_falls_back_when_all_excluded():
    pool = [_entry(1), _entry(2)]
    loads = _loads({"lid1": 1.50, "lid2": 1.60})
    d = decide(pool, loads, None, None, HotLoopState(), Policy(),
               exclude_logical_ids={"lid1", "lid2"})
    # Better a suspect server than none — falls back to the best live one.
    assert d.target.logical_id == "lid1"


def test_no_exclusion_picks_best():
    pool = [_entry(1), _entry(2)]
    loads = _loads({"lid1": 1.90, "lid2": 1.40})  # lid2 best
    d = decide(pool, loads, None, None, HotLoopState(), Policy())
    assert d.target.logical_id == "lid2"
