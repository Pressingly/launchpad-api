"""Unit tests for the pure gate-decision logic."""
import pytest
from src import gate
from src.gate import GateAction, decide_gate


def test_unverified_user_collects():
    assert decide_gate(
        verified=False, email="sid1@askii.ai", sid="sid1", synthetic_domain="askii.ai"
    ) is GateAction.COLLECT


def test_verified_with_real_email_allows():
    assert decide_gate(
        verified=True, email="jane@corp.com", sid="sid1", synthetic_domain="askii.ai"
    ) is GateAction.ALLOW


def test_verified_but_token_still_synthetic_refreshes():
    assert decide_gate(
        verified=True, email="sid1@askii.ai", sid="sid1", synthetic_domain="askii.ai"
    ) is GateAction.REFRESH


def test_real_askii_email_allows_when_not_own_synthetic():
    # A genuine @askii.ai employee whose email is NOT <sid>@askii.ai must ALLOW,
    # not be mistaken for a stale synthetic token. Exact match, not suffix.
    assert decide_gate(
        verified=True, email="real.person@askii.ai", sid="sid1", synthetic_domain="askii.ai"
    ) is GateAction.ALLOW


async def test_verified_state_memoizes_within_ttl(monkeypatch):
    gate._clear_cache()
    calls = {"n": 0}

    async def fake_fetch_user(sid):
        calls["n"] += 1
        return {"verified": True, "real_email": "jane@corp.com"}

    monkeypatch.setattr(gate.db, "fetch_user", fake_fetch_user)

    first = await gate.verified_state("sid1", ttl_seconds=10, now=100.0)
    second = await gate.verified_state("sid1", ttl_seconds=10, now=105.0)  # within TTL

    assert first == (True, "jane@corp.com")
    assert second == (True, "jane@corp.com")
    assert calls["n"] == 1  # second call served from cache, no DB hit


async def test_verified_state_refetches_after_ttl(monkeypatch):
    gate._clear_cache()
    calls = {"n": 0}

    async def fake_fetch_user(sid):
        calls["n"] += 1
        return None

    monkeypatch.setattr(gate.db, "fetch_user", fake_fetch_user)

    await gate.verified_state("sid2", ttl_seconds=10, now=100.0)
    await gate.verified_state("sid2", ttl_seconds=10, now=120.0)  # past TTL

    assert calls["n"] == 2


async def test_evict_drops_the_memo(monkeypatch):
    """The plain case: after evict the next call re-reads the database."""
    gate._clear_cache()
    calls = {"n": 0}

    async def fake_fetch_user(sid):
        calls["n"] += 1
        return None

    monkeypatch.setattr(gate.db, "fetch_user", fake_fetch_user)

    await gate.verified_state("sid3", ttl_seconds=10, now=100.0)
    await gate.verified_state("sid3", ttl_seconds=10, now=101.0)  # cached
    assert calls["n"] == 1

    gate.evict("sid3", now=101.0)
    await gate.verified_state("sid3", ttl_seconds=10, now=102.0)
    assert calls["n"] == 2


async def test_evict_beats_a_lookup_already_in_flight(monkeypatch):
    """The race evict exists for, and the reason a tombstone is needed.

    A lookup that started before the user clicked their verification link
    resumes after it and would otherwise re-insert verified=False with a fresh
    TTL -- bouncing the just-verified user back to the collection page, where
    /api/me reports verified so no modal renders and they see no explanation.
    Popping the cache is not enough: at evict time the entry is not there yet.
    """
    gate._clear_cache()

    async def fake_fetch_user(sid):
        # The click lands while this lookup is suspended on the database.
        gate.evict("sid4", now=100.5)
        return None  # unverified, the answer that is now stale

    monkeypatch.setattr(gate.db, "fetch_user", fake_fetch_user)

    await gate.verified_state("sid4", ttl_seconds=10, now=100.0)

    # The stale answer must not have been memoized.
    assert "sid4" not in gate._cache


async def test_tombstones_do_not_accumulate(monkeypatch):
    """Swept on every write, not only when the cache is full -- with a 10s TTL
    the cache never reaches its size bound, so a sweep nested under that branch
    would never run and leak one float per verification for the container's
    life."""
    gate._clear_cache()

    async def fake_fetch_user(sid):
        return None

    monkeypatch.setattr(gate.db, "fetch_user", fake_fetch_user)

    for i in range(5):
        gate.evict(f"old{i}", now=100.0)
    assert len(gate._tombstones) == 5

    # A later write, well past the TTL, reaps them.
    await gate.verified_state("fresh", ttl_seconds=10, now=200.0)
    assert gate._tombstones == {}
