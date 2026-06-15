"""Tests for GET /api/me."""
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


async def test_me_returns_not_collected(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    response = await client.get(
        "/api/me",
        headers={"X-Auth-Request-Email": f"{sid}@askii.ai"},
    )
    assert response.status_code == 200
    assert response.json() == {"state": "not_collected"}


async def test_me_returns_pending_verification(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    await db.insert_user(sid, "jane@example.com", "Jane", "tok123", expires)

    response = await client.get(
        "/api/me",
        headers={"X-Auth-Request-Email": f"{sid}@askii.ai"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "pending_verification"
    assert body["email"] == "jane@example.com"
    assert body["verification_expires_at"] is not None


async def test_me_returns_verified(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    await db.insert_user(sid, "jane@example.com", "Jane", "tok123", expires)
    await db.mark_verified("tok123")

    response = await client.get(
        "/api/me",
        headers={"X-Auth-Request-Email": f"{sid}@askii.ai"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "verified"
    assert body["email"] == "jane@example.com"
    assert body["verified_at"] is not None


async def test_me_requires_auth_header(client):
    response = await client.get("/api/me")
    assert response.status_code == 400
