"""Tests for GET /api/verify."""
import secrets
from datetime import datetime, timedelta, timezone

from src import db
from tests.conftest import seed_pending

# Rows are seeded with `seed_pending`, which writes sha256(raw) into
# verification_token directly (PRD §1.2). Going through db.insert_user would
# couple these tests to *which layer* hashes, which the PRD deliberately
# leaves to the implementer.


async def test_verify_valid_token_redirects(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    await seed_pending(sid, f"jane-{secrets.token_hex(4)}@example.com", "validtok")

    response = await client.get("/api/verify?token=validtok", follow_redirects=False)
    assert response.status_code == 302
    assert "verified=1" in response.headers["location"]

    user = await db.fetch_user(sid)
    assert user["verified"] is True


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
