"""Tests for POST /api/email/resend and POST /api/dismiss."""
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


async def test_resend_for_pending_user(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    await db.insert_user(sid, "jane@example.com", None, "oldtok", expires)

    response = await client.post(
        "/api/email/resend",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
    )
    assert response.status_code == 200

    user = await db.fetch_user(sid)
    assert user["verification_token"] != "oldtok"


async def test_resend_rejects_already_verified(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    await db.insert_user(sid, "jane@example.com", None, "tok", expires)
    await db.mark_verified("tok")

    response = await client.post(
        "/api/email/resend",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
    )
    assert response.status_code == 400


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
