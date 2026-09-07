"""Tests for GET /api/me."""
import secrets

from src import db
from tests.conftest import seed_pending


async def test_me_returns_not_collected(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    response = await client.get(
        "/api/me",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
    )
    assert response.status_code == 200
    assert response.json() == {"state": "not_collected"}


async def test_me_returns_pending_verification(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    await seed_pending(sid, "jane@example.com", "tok123")

    response = await client.get(
        "/api/me",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "pending_verification"
    assert body["email"] == "jane@example.com"
    assert body["verification_expires_at"] is not None


async def test_me_returns_verified(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    await seed_pending(sid, "jane@example.com", "tok123")
    verified = await client.get("/api/verify?token=tok123", follow_redirects=False)
    assert "verified=1" in verified.headers["location"]

    response = await client.get(
        "/api/me",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "verified"
    assert body["email"] == "jane@example.com"
    assert body["verified_at"] is not None


async def test_me_requires_auth_header(client):
    response = await client.get("/api/me")
    assert response.status_code == 400


async def test_me_pending_includes_display_name(client, cleanup_test_users):
    """The key must not vanish before verification.

    /api/me sets response_model_exclude_none=True, so a field the handler leaves
    at None is dropped from the payload entirely. The pending branch used to omit
    display_name, which meant a client re-opening the modal saw no name and would
    blank one the user had already given.
    """
    sid = f"test_{secrets.token_hex(4)}"
    await seed_pending(sid, "jane@example.com", "tok_dn", display_name="Jane")

    response = await client.get(
        "/api/me",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "pending_verification"
    assert body["display_name"] == "Jane"
