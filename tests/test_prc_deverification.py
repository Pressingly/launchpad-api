"""PRD §6.1 — Re-submitting must not de-verify (§2.3).

`real_email` is the identity every downstream app keys on. Silently resetting
a verified user to unverified orphans their data on the next token refresh, so
a re-submit by an already-verified caller is a terminal 409 and the row is
left untouched.
"""
from src import db
from tests.conftest import new_email, new_sid, seed_relinked, submit

EXPECTED_DETAIL = (
    "This account already has a verified email address. "
    "Contact your administrator to change it."
)


async def _verified_user(raw_client) -> tuple:
    """A relink-complete user. `verified` is what the 409 keys on, and clicking
    the verification link no longer sets it -- only the relink does."""
    sid = new_sid()
    email = new_email("deverify")
    await seed_relinked(sid, email)
    return sid, email


async def test_verified_user_resubmitting_gets_409(raw_client, cleanup_test_users):
    sid, _ = await _verified_user(raw_client)

    response = await submit(raw_client, sid, new_email("newaddr"))

    assert response.status_code == 409
    assert response.json()["detail"] == EXPECTED_DETAIL


async def test_verified_user_resubmitting_keeps_verified_and_original_address(
    raw_client, cleanup_test_users
):
    sid, original = await _verified_user(raw_client)

    await submit(raw_client, sid, new_email("newaddr"))

    user = await db.fetch_user(sid)
    assert user["verified"] is True
    assert user["real_email"] == original
    assert user["verified_at"] is not None


async def test_verified_user_resubmitting_their_own_address_still_gets_409(
    raw_client, cleanup_test_users
):
    """The 409 is about the caller's state, not about the address changing."""
    sid, original = await _verified_user(raw_client)

    response = await submit(raw_client, sid, original)

    assert response.status_code == 409
    user = await db.fetch_user(sid)
    assert user["verified"] is True
