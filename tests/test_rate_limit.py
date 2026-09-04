"""PRD §6.1 — Rate limiting (§4).

This module imports `src.rate_limit` at module level on purpose: until lane 2
lands the module, the whole file is a single collection error rather than a
handful of misleading assertion failures elsewhere.
"""
import logging
import secrets
from datetime import datetime, timezone

import pytest

from src import consent_text, rate_limit  # noqa: F401  (import is the contract check)
from src.config import settings
from tests.conftest import new_email, new_sid, submit


async def test_fourth_submit_within_the_hour_returns_429_with_retry_after(
    client, cleanup_test_users, clean_mailbox
):
    """§4.2: 3 submits per hour per user."""
    sid = new_sid()

    for attempt in range(3):
        response = await submit(client, sid, new_email("rl"))
        assert response.status_code == 202, f"submit {attempt + 1} should be allowed"

    fourth = await submit(client, sid, new_email("rl"))

    assert fourth.status_code == 429
    assert "retry-after" in fourth.headers, "429 must carry a Retry-After header (§4.4)"
    assert int(fourth.headers["retry-after"]) > 0
    assert "Too many requests" in fourth.json()["detail"]


async def test_rate_limit_is_per_user_not_global(client, cleanup_test_users, clean_mailbox):
    sid_a, sid_b = new_sid(), new_sid()
    for _ in range(3):
        assert (await submit(client, sid_a, new_email("rl"))).status_code == 202
    assert (await submit(client, sid_a, new_email("rl"))).status_code == 429

    assert (await submit(client, sid_b, new_email("rl"))).status_code == 202


async def test_rejected_consent_version_does_not_consume_quota(
    client, cleanup_test_users, clean_mailbox
):
    """§4.3: only requests that actually cause a send may count.

    A buggy or cached client must not be able to lock a user out.
    """
    sid = new_sid()

    for _ in range(3):
        rejected = await submit(client, sid, new_email("rl"), version="v1.0")
        assert rejected.status_code == 400

    for attempt in range(3):
        allowed = await submit(client, sid, new_email("rl"))
        assert allowed.status_code == 202, (
            f"submit {attempt + 1} was refused: the rejected requests consumed quota"
        )

    # And the limiter is genuinely active — without this the test passes when
    # no limiter exists at all.
    assert (await submit(client, sid, new_email("rl"))).status_code == 429


async def test_missing_identity_header_does_not_consume_quota(
    client, cleanup_test_users, clean_mailbox
):
    sid = new_sid()
    for _ in range(3):
        bad = await client.post(
            "/api/email",
            headers={"X-Auth-Request-Preferred-Username": ""},
            json={
                "email": new_email("rl"),
                "display_name": None,
                "consent": True,
                "consent_text_version": consent_text.CURRENT_VERSION,
            },
        )
        assert bad.status_code == 400

    for _ in range(3):
        assert (await submit(client, sid, new_email("rl"))).status_code == 202
    assert (await submit(client, sid, new_email("rl"))).status_code == 429


async def test_requests_succeed_and_log_an_error_when_valkey_is_unavailable(
    client, cleanup_test_users, clean_mailbox, valkey_down, caplog
):
    """§4.6: fail open. A limiter outage removes a throttle; it must not deny
    every login-adjacent action."""
    sid = new_sid()

    with caplog.at_level(logging.ERROR):
        statuses = [
            (await submit(client, sid, new_email("rl"))).status_code for _ in range(5)
        ]

    assert statuses == [202] * 5, "the limiter failed closed when Valkey was down"
    assert any(r.levelno >= logging.ERROR for r in caplog.records), (
        "a Valkey outage must be logged at ERROR (§4.6)"
    )


async def test_check_and_increment_never_raises_when_valkey_is_down(valkey_down, caplog):
    """The §7b contract: 'Never raises anything else.'"""
    with caplog.at_level(logging.ERROR):
        assert await rate_limit.check_and_increment("submit", new_sid()) is None
        assert await rate_limit.check_and_increment("resend", new_sid()) is None
    assert any(r.levelno >= logging.ERROR for r in caplog.records)


async def test_global_ceiling_flags_only_the_first_trip_of_the_day(monkeypatch):
    """§4.5, as reconciled by lane 2.

    Lane 4 writes the `rate_limited` audit row but has no Valkey access, so the
    SETNX that elects the first trip is expressed as `is_global`: True exactly
    once per day-bucket, False for every later trip. Same 429, same body, same
    Retry-After either way.
    """
    from src.config import settings

    monkeypatch.setattr(settings, "rate_limit_global_per_day", 2)

    for _ in range(2):
        await rate_limit.check_and_increment("submit", new_sid())

    with pytest.raises(rate_limit.RateLimitExceeded) as first:
        await rate_limit.check_and_increment("submit", new_sid())
    assert first.value.is_global is True

    with pytest.raises(rate_limit.RateLimitExceeded) as second:
        await rate_limit.check_and_increment("submit", new_sid())
    assert second.value.is_global is False
    assert second.value.retry_after_seconds == first.value.retry_after_seconds


async def test_global_ceiling_writes_exactly_one_rate_limited_audit_row(
    client, cleanup_test_users, clean_mailbox, monkeypatch
):
    """§4.5: one audit row per day-bucket, not one per refused request."""
    from src.config import settings

    monkeypatch.setattr(settings, "rate_limit_global_per_day", 1)

    allowed = await submit(client, new_sid(), new_email("rl"))
    assert allowed.status_code == 202

    refused = [
        await submit(client, new_sid(), new_email("rl")) for _ in range(3)
    ]
    assert [r.status_code for r in refused] == [429, 429, 429]

    from src import db

    pool = await db.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetchval(
            "SELECT count(*) FROM foss_users_audit "
            "WHERE action = 'rate_limited' AND synthetic_id LIKE 'test_%'"
        )
    assert rows == 1


async def test_rate_limit_exceeded_exposes_the_contract_fields():
    sid = new_sid()
    for _ in range(3):
        await rate_limit.check_and_increment("submit", sid)

    with pytest.raises(rate_limit.RateLimitExceeded) as excinfo:
        await rate_limit.check_and_increment("submit", sid)

    assert isinstance(excinfo.value.retry_after_seconds, int)
    assert excinfo.value.retry_after_seconds > 0
    assert excinfo.value.is_global is False


async def test_overshooting_consume_does_not_burn_the_daily_alarm(monkeypatch):
    """The once-per-day audit row must survive a concurrent overshoot.

    consume() no longer raises, and it cannot write the audit row itself (no
    database access, by design) -- the endpoint's 429 handler does, and that is
    reached only from check(). So if consume() were allowed to win the SETNX
    that elects the first global trip, it would claim the alarm, swallow its own
    exception, and leave every later check() reporting is_global=False: the
    compliance row lost for good and the key burned until the next UTC day.

    This is the interaction between two separate fixes -- making consume()
    non-raising, and detecting the ceiling in check() -- which is exactly where
    it went wrong the first time.
    """
    monkeypatch.setattr(settings, "rate_limit_global_per_day", 2)
    monkeypatch.setattr(settings, "rate_limit_submit_per_hour", 999)
    monkeypatch.setattr(settings, "rate_limit_submit_per_day", 999)

    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    alarm_key = f"rl:global:{day}:alerted"

    # Fill the ceiling with legitimate sends.
    for _ in range(2):
        await rate_limit.consume("submit", f"test_{secrets.token_hex(4)}")
    assert await rate_limit._client.get(alarm_key) is None

    # Overshoot: a request that had already passed check() pushes it over.
    await rate_limit.consume("submit", f"test_{secrets.token_hex(4)}")
    assert await rate_limit._client.get(alarm_key) is None, (
        "consume() must not elect the first trip -- it cannot audit it"
    )

    # The next real request still elects, so the audit row is still written.
    with pytest.raises(rate_limit.RateLimitExceeded) as exc:
        await rate_limit.check("submit", f"test_{secrets.token_hex(4)}")
    assert exc.value.is_global is True
    assert await rate_limit._client.get(alarm_key) == "1"

    # And only once.
    with pytest.raises(rate_limit.RateLimitExceeded) as exc2:
        await rate_limit.check("submit", f"test_{secrets.token_hex(4)}")
    assert exc2.value.is_global is False
