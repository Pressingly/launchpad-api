"""Tests for GET /api/verify."""
import pytest
import secrets
from datetime import datetime, timedelta, timezone

from src import db


@pytest.fixture
async def cleanup_test_users():
    yield
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM foss_users WHERE synthetic_id LIKE 'test_%'")
        await conn.execute("DELETE FROM foss_users_audit WHERE synthetic_id LIKE 'test_%'")


async def test_verify_valid_token_redirects(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    await db.insert_user(sid, "jane@example.com", None, "validtok", expires)

    response = await client.get("/api/verify?token=validtok", follow_redirects=False)
    assert response.status_code == 302
    assert "verified=1" in response.headers["location"]

    user = await db.fetch_user(sid)
    assert user["verified"] is True


async def test_verify_expired_token_redirects_with_error(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    expires = datetime.now(timezone.utc) - timedelta(hours=1)
    await db.insert_user(sid, "jane@example.com", None, "expiredtok", expires)

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
