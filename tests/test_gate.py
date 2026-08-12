"""Unit tests for the pure gate-decision logic."""
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
