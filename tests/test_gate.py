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
