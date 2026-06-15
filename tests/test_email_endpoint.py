"""Tests for POST /api/email."""
import pytest
import secrets

from src import db


@pytest.fixture
async def cleanup_test_users():
    yield
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM foss_users WHERE synthetic_id LIKE 'test_%'")
        await conn.execute("DELETE FROM foss_users_audit WHERE synthetic_id LIKE 'test_%'")


async def test_submit_email_creates_user_and_audit(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    response = await client.post(
        "/api/email",
        headers={"X-Auth-Request-Email": f"{sid}@askii.ai"},
        json={
            "email": "jane@example.com",
            "display_name": "Jane",
            "consent": True,
            "consent_text_version": "v1.0",
        },
    )
    assert response.status_code == 202
    body = response.json()
    assert body["state"] == "pending_verification"

    user = await db.fetch_user(sid)
    assert user is not None
    assert user["real_email"] == "jane@example.com"
    assert user["verified"] is False
    assert user["verification_token"] is not None


async def test_submit_email_rejects_bad_email(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    response = await client.post(
        "/api/email",
        headers={"X-Auth-Request-Email": f"{sid}@askii.ai"},
        json={
            "email": "not-an-email",
            "display_name": None,
            "consent": True,
            "consent_text_version": "v1.0",
        },
    )
    assert response.status_code == 422


async def test_submit_email_rejects_no_consent(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    response = await client.post(
        "/api/email",
        headers={"X-Auth-Request-Email": f"{sid}@askii.ai"},
        json={
            "email": "jane@example.com",
            "display_name": None,
            "consent": False,
            "consent_text_version": "v1.0",
        },
    )
    assert response.status_code == 422


async def test_submit_email_rejects_unknown_consent_version(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    response = await client.post(
        "/api/email",
        headers={"X-Auth-Request-Email": f"{sid}@askii.ai"},
        json={
            "email": "jane@example.com",
            "display_name": None,
            "consent": True,
            "consent_text_version": "v99.999",
        },
    )
    assert response.status_code == 400


async def test_submit_email_idempotent_for_unverified(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    for email in ["first@example.com", "second@example.com"]:
        response = await client.post(
            "/api/email",
            headers={"X-Auth-Request-Email": f"{sid}@askii.ai"},
            json={
                "email": email,
                "display_name": None,
                "consent": True,
                "consent_text_version": "v1.0",
            },
        )
        assert response.status_code == 202

    user = await db.fetch_user(sid)
    assert user["real_email"] == "second@example.com"
