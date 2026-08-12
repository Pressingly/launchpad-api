"""Integration tests for the edge verify-gate endpoint GET /api/authz."""
import secrets
from datetime import datetime, timedelta, timezone

import pytest

from src import db, gate


@pytest.fixture
async def cleanup_test_users():
    yield
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM foss_users WHERE synthetic_id LIKE 'test_%'")
        await conn.execute("DELETE FROM foss_users_audit WHERE synthetic_id LIKE 'test_%'")


async def _mk_verified(sid: str, email: str):
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    await db.insert_user(sid, email, "Jane", "tok_" + sid, expires)
    await db.mark_verified("tok_" + sid)


async def test_authz_allows_verified_real_email(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    await _mk_verified(sid, "jane@corp.com")
    gate._clear_cache()
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Preferred-Username": sid,
            "X-Auth-Request-Email": "jane@corp.com",
            "Accept": "text/html",
        },
    )
    assert r.status_code == 200


async def test_authz_redirects_unverified_browser_to_collect(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    gate._clear_cache()
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Preferred-Username": sid,
            "X-Auth-Request-Email": f"{sid}@askii.ai",
            "Accept": "text/html",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "/?collect=1" in r.headers["location"]


async def test_authz_403_json_for_unverified_api_client(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    gate._clear_cache()
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Preferred-Username": sid,
            "X-Auth-Request-Email": f"{sid}@askii.ai",
            "Accept": "application/json",
        },
    )
    assert r.status_code == 403
    assert r.json()["error"] == "email_verification_required"


async def test_authz_refreshes_stale_synthetic_token(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    await _mk_verified(sid, "jane@corp.com")  # verified in DB...
    gate._clear_cache()
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Preferred-Username": sid,
            "X-Auth-Request-Email": f"{sid}@askii.ai",  # ...but token still synthetic
            "Accept": "text/html",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "pm.foss.local.dev",
            "X-Forwarded-Uri": "/projects",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert r.headers["location"].startswith(
        "https://pm.foss.local.dev/oauth2/sign_in?prompt=none&rd="
    )


async def test_authz_allows_stale_token_for_api_client(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    await _mk_verified(sid, "jane@corp.com")
    gate._clear_cache()
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Preferred-Username": sid,
            "X-Auth-Request-Email": f"{sid}@askii.ai",
            "Accept": "application/json",
        },
    )
    assert r.status_code == 200


async def test_authz_missing_identity_is_401(client):
    r = await client.get("/api/authz", headers={"Accept": "text/html"})
    assert r.status_code == 401
