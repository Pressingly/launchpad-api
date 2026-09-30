"""Tests for GET /api/verify."""
import secrets
from datetime import datetime, timedelta, timezone

from src import db
from src.config import RELINK_SKIP, settings
from tests.conftest import relink_state, seed_pending, seed_relinked

# Rows are seeded with `seed_pending`, which writes sha256(raw) into
# verification_token directly (PRD §1.2). Going through db.insert_user would
# couple these tests to *which layer* hashes, which the PRD deliberately
# leaves to the implementer.


async def test_verify_valid_token_redirects(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    await seed_pending(sid, f"jane-{secrets.token_hex(4)}@example.com", "validtok")

    response = await client.get("/api/verify?token=validtok", follow_redirects=False)
    assert response.status_code == 302
    # Not ?verified=1: the portal treats that as "your address is live now" and
    # fires a full re-authentication to pick up a claim that has not changed.
    assert "relinking=1" in response.headers["location"]


async def test_verify_moves_the_user_to_pending_relink_and_not_to_verified(
    client, cleanup_test_users
):
    """THE invariant, at the endpoint. A user whose relink has not completed
    must never reach an app carrying their real email -- and the overlay serves
    the real address on `verified` alone, so /api/verify must not set it."""
    sid = f"test_{secrets.token_hex(4)}"
    await seed_pending(sid, f"jane-{secrets.token_hex(4)}@example.com", "invtok")

    await client.get("/api/verify?token=invtok", follow_redirects=False)

    user = await db.fetch_user(sid)
    assert user["verified"] is False
    assert user["verified_at"] is None
    assert await relink_state(sid) == "pending_relink"


async def test_the_overlay_query_returns_nothing_for_a_pending_relink_user(
    client, cleanup_test_users
):
    """Asserted against the real SQL mpass-auth-proxy runs, not a mock.

    `SELECT real_email FROM foss_users WHERE synthetic_id = $1 AND verified`
    is the whole overlay contract. If it returned a row here, every app would
    see the real address before the relink and create the duplicate account
    this state machine exists to prevent.
    """
    sid = f"test_{secrets.token_hex(4)}"
    email = f"jane-{secrets.token_hex(4)}@example.com"
    await seed_pending(sid, email, "overlaytok")
    await client.get("/api/verify?token=overlaytok", follow_redirects=False)

    pool = await db.get_pool()
    async with pool.acquire() as conn:
        overlaid = await conn.fetchval(
            "SELECT real_email FROM foss_users "
            "WHERE synthetic_id = $1 AND verified = TRUE",
            sid,
        )
    assert overlaid is None

    # ... and it starts returning the address once the relink completes.
    await db.mark_relinked(sid)
    async with pool.acquire() as conn:
        overlaid = await conn.fetchval(
            "SELECT real_email FROM foss_users "
            "WHERE synthetic_id = $1 AND verified = TRUE",
            sid,
        )
    assert overlaid == email


async def test_verify_expired_token_leaves_the_state_untouched(
    client, cleanup_test_users
):
    """An expired or invalid token still fails, unchanged by the split."""
    sid = f"test_{secrets.token_hex(4)}"
    expires = datetime.now(timezone.utc) - timedelta(hours=1)
    await seed_pending(
        sid, f"jane-{secrets.token_hex(4)}@example.com", "deadtok", expires=expires
    )

    await client.get("/api/verify?token=deadtok", follow_redirects=False)

    assert (await db.fetch_user(sid))["verified"] is False
    assert await relink_state(sid) == "none"


async def test_verify_expired_token_redirects_with_error(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    expires = datetime.now(timezone.utc) - timedelta(hours=1)
    await seed_pending(
        sid, f"jane-{secrets.token_hex(4)}@example.com", "expiredtok", expires=expires
    )

    response = await client.get("/api/verify?token=expiredtok", follow_redirects=False)
    assert response.status_code == 302
    assert "verify_error=expired_or_invalid" in response.headers["location"]


async def test_verify_unknown_token_redirects_with_error(client):
    response = await client.get("/api/verify?token=nonexistent", follow_redirects=False)
    assert response.status_code == 302
    assert "verify_error=expired_or_invalid" in response.headers["location"]


async def test_verify_missing_token_returns_422(client):
    response = await client.get("/api/verify")
    assert response.status_code == 422


async def test_skip_mode_completes_the_user_and_re_signs_them_in(
    client, cleanup_test_users, monkeypatch
):
    """LAUNCHPAD_RELINK_RUNNER=skip: no app accounts exist to move, so the click
    completes the user and the portal re-runs sign-in to pick up the address."""
    monkeypatch.setattr(settings, "launchpad_relink_runner", RELINK_SKIP)
    sid = f"test_{secrets.token_hex(4)}"
    await seed_pending(sid, f"jane-{secrets.token_hex(4)}@example.com", "skiptok")

    response = await client.get("/api/verify?token=skiptok", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["location"].endswith("?verified=1")
    user = await db.fetch_user(sid)
    assert user["verified"] is True
    assert user["verified_at"] is not None
    assert await relink_state(sid) == "relinked"


async def test_skip_mode_still_refuses_an_address_another_account_verified(
    client, cleanup_test_users, monkeypatch
):
    monkeypatch.setattr(settings, "launchpad_relink_runner", RELINK_SKIP)
    email = f"taken-{secrets.token_hex(4)}@example.com"
    await seed_relinked(f"test_{secrets.token_hex(4)}", email)
    sid = f"test_{secrets.token_hex(4)}"
    await seed_pending(sid, email, "skiptaken")

    response = await client.get("/api/verify?token=skiptaken", follow_redirects=False)

    assert "verify_error=email_taken" in response.headers["location"]
    # Consuming and completing are one transaction, so the refusal (here the
    # verified-address index firing on the completing UPDATE) rolls the whole
    # click back: the user keeps a working link and is not left token-less in
    # pending_relink, which nothing completes under skip.
    user = await db.fetch_user(sid)
    assert user["verified"] is False
    assert user["verification_token"] is not None
    assert await relink_state(sid) == "none"


async def test_skip_mode_writes_the_verify_audit_row(
    client, cleanup_test_users, admin_conn, monkeypatch
):
    monkeypatch.setattr(settings, "launchpad_relink_runner", RELINK_SKIP)
    sid = f"test_{secrets.token_hex(4)}"
    await seed_pending(sid, f"jane-{secrets.token_hex(4)}@example.com", "skipaudit")

    await client.get("/api/verify?token=skipaudit", follow_redirects=False)

    actions = await admin_conn.fetch(
        "SELECT action FROM foss_users_audit WHERE synthetic_id = $1", sid
    )
    assert [row["action"] for row in actions] == ["verify_email"]


async def test_skip_mode_leaves_an_expired_token_unconsumed(
    client, cleanup_test_users, monkeypatch
):
    monkeypatch.setattr(settings, "launchpad_relink_runner", RELINK_SKIP)
    sid = f"test_{secrets.token_hex(4)}"
    expired = datetime.now(timezone.utc) - timedelta(hours=1)
    await seed_pending(sid, f"jane-{secrets.token_hex(4)}@example.com", "skipold", expires=expired)

    response = await client.get("/api/verify?token=skipold", follow_redirects=False)

    assert "verify_error=expired_or_invalid" in response.headers["location"]
    assert (await db.fetch_user(sid))["verified"] is False


async def test_skip_mode_does_not_complete_a_user_an_operator_is_holding(
    client, cleanup_test_users, admin_conn, monkeypatch
):
    """A user parked in pending_relink (relink not done yet) who gets a fresh
    link through resend must not complete themselves once skip is on."""
    monkeypatch.setattr(settings, "launchpad_relink_runner", RELINK_SKIP)
    sid = f"test_{secrets.token_hex(4)}"
    await seed_pending(sid, f"jane-{secrets.token_hex(4)}@example.com", "heldtok")
    await admin_conn.execute(
        "UPDATE foss_users SET relink_state = 'pending_relink' WHERE synthetic_id = $1", sid
    )

    response = await client.get("/api/verify?token=heldtok", follow_redirects=False)

    assert "verify_error=expired_or_invalid" in response.headers["location"]
    assert (await db.fetch_user(sid))["verified"] is False
    assert await relink_state(sid) == "pending_relink"
