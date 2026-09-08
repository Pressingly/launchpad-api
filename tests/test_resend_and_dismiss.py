"""Tests for POST /api/email/resend and POST /api/dismiss."""
import secrets

from src import db
from tests.conftest import seed_pending


async def test_resend_for_pending_user(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    await seed_pending(sid, f"jane-{secrets.token_hex(4)}@example.com", "oldtok")
    before = (await db.fetch_user(sid))["verification_token"]

    response = await client.post(
        "/api/email/resend",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
    )
    assert response.status_code == 200

    user = await db.fetch_user(sid)
    assert user["verification_token"] != before


async def test_resend_rejects_already_verified(client, cleanup_test_users):
    """409, not the 400 this returned before PRD §5 — one user state, one
    status code, matching §2.3's 409 for the same state on submit."""
    sid = f"test_{secrets.token_hex(4)}"
    await seed_pending(sid, f"jane-{secrets.token_hex(4)}@example.com", "tok")
    verified = await client.get("/api/verify?token=tok", follow_redirects=False)
    assert "verified=1" in verified.headers["location"]

    response = await client.post(
        "/api/email/resend",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
    )
    assert response.status_code == 409


async def test_resend_rejects_not_collected(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    response = await client.post(
        "/api/email/resend",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
    )
    assert response.status_code == 400


async def test_dismiss_is_retired_410(client):
    sid = f"test_{secrets.token_hex(4)}"
    response = await client.post(
        "/api/dismiss",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
    )
    assert response.status_code == 410
