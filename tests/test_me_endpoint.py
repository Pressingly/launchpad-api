"""Tests for GET /api/me."""
import secrets

from src import db
from tests.conftest import seed_pending, seed_relinked


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


async def test_me_returns_relinking_after_the_link_is_clicked(
    client, cleanup_test_users
):
    """The new state. The user has proved they control the address but their
    app accounts have not been moved yet, so they are neither pending
    verification nor verified."""
    sid = f"test_{secrets.token_hex(4)}"
    await seed_pending(sid, "jane@example.com", "tok_relinking")
    clicked = await client.get("/api/verify?token=tok_relinking", follow_redirects=False)
    assert "relinking=1" in clicked.headers["location"]

    response = await client.get(
        "/api/me",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "relinking"
    # The panel names the address being set up.
    assert body["email"] == "jane@example.com"


async def test_me_returns_relink_failed(client, cleanup_test_users):
    """A relink the runner refused. Distinct from 'relinking' so the portal can
    tell the user an administrator has been notified, rather than "still
    working on it"."""
    sid = f"test_{secrets.token_hex(4)}"
    await seed_pending(sid, "jane@example.com", "tok_relink_failed")
    assert await db.mark_pending_relink(
        db.hash_token("tok_relink_failed"), None, None
    ) == sid
    assert await db.mark_relink_failed(sid, "collision with another account") is True

    response = await client.get(
        "/api/me",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "relink_failed"
    assert body["email"] == "jane@example.com"
    # The refusal detail can name another account's address -- not the
    # caller's business, so it must never appear in this response.
    assert "relink_error" not in body
    assert "collision" not in response.text


async def test_me_returns_verified_once_the_relink_completes(
    client, cleanup_test_users
):
    """A relinked user is released: verified, and no longer held."""
    sid = f"test_{secrets.token_hex(4)}"
    await seed_relinked(sid, "jane@example.com")

    response = await client.get(
        "/api/me",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
    )
    assert response.json()["state"] == "verified"


async def test_me_holds_a_verified_user_whose_relink_is_outstanding(
    client, cleanup_test_users
):
    """(verified = TRUE, relink_state = 'pending_relink') -- the state a manual
    override leaves behind when it is interrupted between ops_override_write
    and mark_relinked.

    This is what pins the handler's branch ordering. The sibling test above
    seeds ('relinked', TRUE), which the pending_relink branch never matches in
    either order, so it cannot detect a swap. decide_gate orders the same way
    and returns RELINKING here; if /api/me answered "verified" instead, the
    portal would render the verified view while the gate kept bouncing the
    user, with nothing on screen explaining why.
    """
    sid = f"test_{secrets.token_hex(4)}"
    await seed_relinked(sid, "jane@example.com")
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE foss_users SET relink_state = 'pending_relink' "
            "WHERE synthetic_id = $1",
            sid,
        )
    assert (await db.fetch_user(sid))["verified"] is True

    response = await client.get(
        "/api/me",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
    )
    assert response.json()["state"] == "relinking"


async def test_me_returns_verified_for_the_legacy_combination(
    client, cleanup_test_users
):
    """verified = true, relink_state = 'none' -- a user who verified before the
    column existed. Complete, not stuck."""
    sid = f"test_{secrets.token_hex(4)}"
    await seed_pending(sid, "legacy@example.com", "tok_legacy_me")
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE foss_users SET verified = TRUE, verified_at = now() "
            "WHERE synthetic_id = $1",
            sid,
        )

    response = await client.get(
        "/api/me",
        headers={"X-Auth-Request-Preferred-Username": f"{sid}"},
    )
    assert response.json()["state"] == "verified"


async def test_me_returns_verified(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    await seed_relinked(sid, "jane@example.com")

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
