"""Tests for POST /api/email."""
import pytest
import secrets

from src import consent_text, db


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
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
        json={
            "email": "jane@example.com",
            "display_name": "Jane",
            "consent": True,
            "consent_text_version": consent_text.CURRENT_VERSION,
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
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
        json={
            "email": "not-an-email",
            "display_name": None,
            "consent": True,
            "consent_text_version": consent_text.CURRENT_VERSION,
        },
    )
    assert response.status_code == 422


async def test_submit_email_rejects_no_consent(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    response = await client.post(
        "/api/email",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
        json={
            "email": "jane@example.com",
            "display_name": None,
            "consent": False,
            "consent_text_version": consent_text.CURRENT_VERSION,
        },
    )
    assert response.status_code == 422


async def test_submit_email_rejects_unknown_consent_version(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    response = await client.post(
        "/api/email",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
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
            headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
            json={
                "email": email,
                "display_name": None,
                "consent": True,
                "consent_text_version": consent_text.CURRENT_VERSION,
            },
        )
        assert response.status_code == 202

    user = await db.fetch_user(sid)
    assert user["real_email"] == "second@example.com"


async def test_submit_email_duplicate_across_accounts_returns_409(client, cleanup_test_users):
    """A second synthetic_id submitting an email another account already
    registered must get a clean 409 (not an uncaught UniqueViolation -> 500)."""
    email = "shared-alias@example.com"
    sid1 = f"test_{secrets.token_hex(4)}"
    sid2 = f"test_{secrets.token_hex(4)}"

    first = await client.post(
        "/api/email",
        headers={"X-Auth-Request-Preferred-Username": sid1},
        json={"email": email, "display_name": None, "consent": True, "consent_text_version": consent_text.CURRENT_VERSION},
    )
    assert first.status_code == 202

    second = await client.post(
        "/api/email",
        headers={"X-Auth-Request-Preferred-Username": sid2},
        json={"email": email, "display_name": None, "consent": True, "consent_text_version": consent_text.CURRENT_VERSION},
    )
    assert second.status_code == 409
    assert "already registered" in second.json()["detail"].lower()

    # The second account must not have been created by the failed insert.
    assert await db.fetch_user(sid2) is None


async def test_submit_email_audit_records_forwarded_client_ip(client, cleanup_test_users):
    """The consent audit must record the real client IP from X-Forwarded-For
    (left-most entry), not the internal proxy hop."""
    sid = f"test_{secrets.token_hex(4)}"
    response = await client.post(
        "/api/email",
        headers={
            "X-Auth-Request-Preferred-Username": sid,
            "X-Forwarded-For": "203.0.113.7, 172.18.0.5",
        },
        json={"email": "fwd@example.com", "display_name": None, "consent": True, "consent_text_version": consent_text.CURRENT_VERSION},
    )
    assert response.status_code == 202

    pool = await db.get_pool()
    async with pool.acquire() as conn:
        ip = await conn.fetchval(
            "SELECT ip_address FROM foss_users_audit "
            "WHERE synthetic_id = $1 AND action = 'submit_email'",
            sid,
        )
    assert str(ip) == "203.0.113.7"


async def test_retired_consent_version_is_rejected(client, cleanup_test_users):
    """v1.0 named an app that has since been removed from the bundle and omitted
    one that was added. It stays in CONSENT_TEXTS so historical audit rows still
    render, but accepting it would let a stale client keep writing consent
    records for the wrong roster."""
    sid = f"test_{secrets.token_hex(4)}"
    resp = await client.post(
        "/api/email",
        json={
            "email": f"retired-{secrets.token_hex(4)}@example.com",
            "consent": True,
            "consent_text_version": "v1.0",
        },
        headers={"X-Auth-Request-Preferred-Username": sid},
    )
    assert resp.status_code == 400
    assert consent_text.CURRENT_VERSION in resp.json()["detail"]


async def test_current_consent_version_is_accepted(client, cleanup_test_users):
    # Unique sid and address: real_email is uniquely indexed, so a fixed one
    # would be permanently claimed by this test's row against a persistent
    # database and 409 every later test that reused it.
    sid = f"test_{secrets.token_hex(4)}"
    resp = await client.post(
        "/api/email",
        json={
            "email": f"current-{secrets.token_hex(4)}@example.com",
            "consent": True,
            "consent_text_version": consent_text.CURRENT_VERSION,
        },
        headers={"X-Auth-Request-Preferred-Username": sid},
    )
    assert resp.status_code == 202


def test_current_version_is_present_in_consent_texts():
    """Guard: CURRENT_VERSION must resolve, or every submission 500s on get_text."""
    assert consent_text.CURRENT_VERSION in consent_text.CONSENT_TEXTS
    assert "v1.0" in consent_text.CONSENT_TEXTS
    assert not consent_text.is_valid_version("v1.0")
