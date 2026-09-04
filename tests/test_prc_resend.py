"""PRD §6.1 — Resend (§5).

The old flow was fetch → check → rotate across three pool acquisitions. The
required flow is one conditional UPDATE that both checks and rotates, with the
audit write in the same transaction.

Note on concurrency: both UPDATEs *succeed* (each sees verified = FALSE) and
the later one wins. That is the correct outcome — exactly one live token — so
these tests assert the outcome, not "one rotation succeeded".
"""
import asyncio

import pytest

from src import db
from tests.conftest import (
    latest_token,
    mailpit_messages,
    mailpit_token,
    new_email,
    new_sid,
    seed_pending,
    sha256_hex,
    submit,
)


async def _resend(ac, sid):
    return await ac.post(
        "/api/email/resend",
        headers={"X-Auth-Request-Preferred-Username": sid},
    )


async def test_concurrent_resends_leave_exactly_one_live_token(
    raw_client, cleanup_test_users, clean_mailbox, valkey_down
):
    """After two concurrent resends exactly one token verifies, and it is the
    one in the most recently delivered mailpit message.

    `valkey_down` is requested deliberately: §4.2 limits resend to 1 per 60
    seconds, which would make the second of two concurrent resends a 429 and
    the case untestable. With the limiter failing open (§4.6) the concurrency
    itself is what is under test.
    """
    sid = new_sid()
    email = new_email("resend")
    await seed_pending(sid, email, "tok-original")

    first, second = await asyncio.gather(_resend(raw_client, sid), _resend(raw_client, sid))
    assert {first.status_code, second.status_code} == {200}

    messages = await mailpit_messages()  # newest first
    assert len(messages) == 2, f"expected two resend emails, got {len(messages)}"
    winner = await mailpit_token(messages[0]["ID"])
    loser = await mailpit_token(messages[1]["ID"])
    assert winner != loser

    stored = (await db.fetch_user(sid))["verification_token"]
    assert stored == sha256_hex(winner), (
        "the newest delivered message does not hold the live token — UPDATE "
        "commit order and SMTP arrival order diverged"
    )

    stale = await raw_client.get(f"/api/verify?token={loser}", follow_redirects=False)
    assert "verify_error=expired_or_invalid" in stale.headers["location"]

    live = await raw_client.get(f"/api/verify?token={winner}", follow_redirects=False)
    assert "verified=1" in live.headers["location"]
    assert (await db.fetch_user(sid))["verified"] is True


async def test_resend_refreshes_verification_expires(
    raw_client, cleanup_test_users, clean_mailbox
):
    """Not only the token: a stale expiry would make the fresh link dead on
    arrival."""
    from datetime import datetime, timedelta, timezone

    sid = new_sid()
    email = new_email("resend")
    near_expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
    await seed_pending(sid, email, "tok-nearly-dead", expires=near_expiry)

    before = (await db.fetch_user(sid))["verification_expires"]
    assert (await _resend(raw_client, sid)).status_code == 200
    after = (await db.fetch_user(sid))["verification_expires"]

    assert after > before, "resend rotated the token but left the old expiry"


async def test_resend_already_verified_returns_409(raw_client, cleanup_test_users):
    """Deliberate API change (§5): one user state, one status code — 409, to
    match §2.3's 409 on submit."""
    sid = new_sid()
    await seed_pending(sid, new_email("resend"), "tok-verify-me")
    await raw_client.get("/api/verify?token=tok-verify-me", follow_redirects=False)

    response = await _resend(raw_client, sid)

    assert response.status_code == 409
    assert response.json()["detail"] == "Already verified"


async def test_resend_writes_audit_in_the_same_transaction(
    raw_client, cleanup_test_users, clean_mailbox, admin_conn
):
    """If the audit insert fails, the token must not have been rotated."""
    sid = new_sid()
    await seed_pending(sid, new_email("resend"), "tok-atomic-resend")
    before = (await db.fetch_user(sid))["verification_token"]

    await admin_conn.execute("REVOKE INSERT ON foss_users_audit FROM launchpad_api_user")
    try:
        response = await _resend(raw_client, sid)
    finally:
        await admin_conn.execute("GRANT INSERT ON foss_users_audit TO launchpad_api_user")

    assert response.status_code != 200
    assert (await db.fetch_user(sid))["verification_token"] == before
