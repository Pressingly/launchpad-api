"""Tests for the database connection layer.

Updated for the PRD's transactional surface: `insert_user` is gone (folded
into `submit_email`, which also writes the audit row in the same transaction),
tokens are stored as `hash_token(raw)`, and the resend path raises rather than
returning a bool.
"""
import re
import secrets
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest

from src import consent_text
from src.db import (
    AlreadyVerified,
    EmailAlreadyRegistered,
    NoSubmissionYet,
    close_pool,
    fetch_user,
    get_pool,
    hash_token,
    insert_audit,
    mark_pending_relink,
    mark_relink_failed,
    mark_relinked,
    next_pending_relink,
    rotate_verification_token,
    submit_email,
)


def _sid() -> str:
    return f"test_{secrets.token_hex(4)}"


def _email() -> str:
    return f"db-{secrets.token_hex(6)}@example.com"


def _in_a_day() -> datetime:
    return datetime.now(timezone.utc) + timedelta(hours=24)


async def _submit(sid: str, email: str, raw_token: str, expires=None, display_name=None):
    await submit_email(
        synthetic_id=sid,
        email=email,
        display_name=display_name,
        token_hash=hash_token(raw_token),
        verification_expires=expires or _in_a_day(),
        consent_text_version=consent_text.CURRENT_VERSION,
        consent_text_content=consent_text.get_text(consent_text.CURRENT_VERSION),
        ip_address="127.0.0.1",
        user_agent="pytest",
    )


async def _relink(sid: str, raw_token: str) -> None:
    """Take a submitted user all the way to relinked, the way the flow will:
    the token click moves them to pending_relink, the relink completes them."""
    assert await mark_pending_relink(hash_token(raw_token), None, None) == sid
    assert await mark_relinked(sid) is True


async def _state(sid: str) -> str:
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.fetchval(
            "SELECT relink_state FROM foss_users WHERE synthetic_id = $1", sid
        )


async def test_pool_can_query():
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.fetchval("SELECT 1")
    assert result == 1


def test_hash_token_is_lowercase_sha256_hex():
    digest = hash_token("some-raw-token")
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert digest == hash_token("some-raw-token")
    assert digest != hash_token("some-other-token")


async def test_submit_email_creates_row_and_audit(cleanup_test_users):
    sid, email = _sid(), _email()
    await _submit(sid, email, "tok123", display_name="Test User")

    user = await fetch_user(sid)
    assert user is not None
    assert user["real_email"] == email
    assert user["display_name"] == "Test User"
    assert user["verified"] is False
    assert user["verification_token"] == hash_token("tok123")

    pool = await get_pool()
    async with pool.acquire() as conn:
        actions = [
            r["action"]
            for r in await conn.fetch(
                "SELECT action FROM foss_users_audit WHERE synthetic_id = $1", sid
            )
        ]
    assert actions == ["submit_email"]


async def test_submit_email_raises_already_verified_for_a_verified_caller(
    cleanup_test_users,
):
    sid, email = _sid(), _email()
    await _submit(sid, email, "tok-verify")
    await _relink(sid, "tok-verify")

    with pytest.raises(AlreadyVerified):
        await _submit(sid, _email(), "tok-again")

    user = await fetch_user(sid)
    assert user["verified"] is True
    assert user["real_email"] == email


async def test_submit_email_does_not_raise_on_a_duplicate_address(cleanup_test_users):
    """The partial index makes unverified claims non-binding, so the old
    EmailAlreadyRegistered path is unreachable from the submit side."""
    email = _email()
    sid1, sid2 = _sid(), _sid()
    await _submit(sid1, email, "tok-a")
    await _submit(sid2, email, "tok-b")

    assert (await fetch_user(sid1))["real_email"] == email
    assert (await fetch_user(sid2))["real_email"] == email


async def test_submit_email_writes_a_collision_row_instead_of_a_consent_row(
    cleanup_test_users,
):
    email = _email()
    victim, prober = _sid(), _sid()
    await _submit(victim, email, "tok-victim")
    await _relink(victim, "tok-victim")

    await _submit(prober, email, "tok-prober")

    pool = await get_pool()
    async with pool.acquire() as conn:
        actions = [
            r["action"]
            for r in await conn.fetch(
                "SELECT action FROM foss_users_audit WHERE synthetic_id = $1", prober
            )
        ]
    assert actions == ["submit_email_collision"]


async def test_fetch_user_not_found(cleanup_test_users):
    assert await fetch_user("test_nonexistent_xyz") is None


async def test_mark_pending_relink_with_valid_token(cleanup_test_users):
    sid = _sid()
    await _submit(sid, _email(), "good_token")

    assert await mark_pending_relink(hash_token("good_token"), None, None) == sid

    user = await fetch_user(sid)
    assert user["verification_token"] is None
    assert user["relink_state"] == "pending_relink"


async def test_mark_pending_relink_does_not_set_verified(cleanup_test_users):
    """THE invariant. Consuming the token proves the user controls the address;
    it does not move their app accounts onto it. The mpass overlay selects
    WHERE verified = TRUE, so setting verified here is exactly what handed the
    real address to five apps that each then created a second account."""
    sid = _sid()
    await _submit(sid, _email(), "inv_token")

    await mark_pending_relink(hash_token("inv_token"), None, None)

    user = await fetch_user(sid)
    assert user["verified"] is False
    assert user["verified_at"] is None
    assert user["relink_state"] == "pending_relink"


async def test_mark_pending_relink_writes_the_verify_email_audit_row(
    cleanup_test_users,
):
    sid = _sid()
    await _submit(sid, _email(), "audited_token")
    await mark_pending_relink(hash_token("audited_token"), "203.0.113.4", "pytest")

    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT ip_address, user_agent FROM foss_users_audit "
            "WHERE synthetic_id = $1 AND action = 'verify_email'",
            sid,
        )
    assert row is not None
    assert str(row["ip_address"]) == "203.0.113.4"


async def test_mark_pending_relink_with_expired_token(cleanup_test_users):
    sid = _sid()
    expired = datetime.now(timezone.utc) - timedelta(hours=1)
    await _submit(sid, _email(), "expired_token", expires=expired)

    assert await mark_pending_relink(hash_token("expired_token"), None, None) is None
    assert await _state(sid) == "none"


async def test_mark_pending_relink_rejects_the_raw_token_lookalike(
    cleanup_test_users,
):
    """The column holds a digest, so passing the raw value finds nothing."""
    sid = _sid()
    await _submit(sid, _email(), "raw_token")

    assert await mark_pending_relink("raw_token", None, None) is None
    assert (await fetch_user(sid))["verified"] is False
    assert await _state(sid) == "none"


async def test_mark_pending_relink_raises_when_another_account_owns_the_address(
    cleanup_test_users,
):
    """Still raised at click time even though the partial index can no longer
    fire here -- verified is not set by this statement any more, so the check is
    an explicit probe. Catching it early is better UX; it is no longer the
    enforcement, which is why mark_relinked raises too."""
    email = _email()
    first, second = _sid(), _sid()
    await _submit(first, email, "tok-first")
    await _submit(second, email, "tok-second")
    await _relink(first, "tok-first")

    with pytest.raises(EmailAlreadyRegistered):
        await mark_pending_relink(hash_token("tok-second"), None, None)

    assert (await fetch_user(second))["verified"] is False
    # The whole statement rolled back: the loser keeps their token rather than
    # being left in 'none' with nothing to click.
    assert await _state(second) == "none"
    assert (await fetch_user(second))["verification_token"] == hash_token("tok-second")


async def test_mark_relinked_sets_both_columns(cleanup_test_users):
    """The ONLY path that sets verified, and it sets relink_state with it -- in
    one statement, so the two cannot separate."""
    sid = _sid()
    await _submit(sid, _email(), "tok-relink")
    assert await mark_pending_relink(hash_token("tok-relink"), None, None) == sid

    assert await mark_relinked(sid) is True

    user = await fetch_user(sid)
    assert user["verified"] is True
    assert user["verified_at"] is not None
    assert user["relink_state"] == "relinked"


async def test_relink_is_the_only_path_that_sets_verified(cleanup_test_users):
    """Guards the split by construction: the old entry point is gone, not
    aliased. A caller that sets verified without relinking is precisely the bug
    the split exists to prevent, so its absence is asserted rather than
    assumed."""
    from src import db as db_module

    assert not hasattr(db_module, "mark_" + "verified")

    sid = _sid()
    await _submit(sid, _email(), "tok-only")
    await mark_pending_relink(hash_token("tok-only"), None, None)
    assert (await fetch_user(sid))["verified"] is False

    await mark_relinked(sid)
    assert (await fetch_user(sid))["verified"] is True


async def test_mark_relinked_is_idempotent(cleanup_test_users):
    """An operator or a runner must be able to retry without knowing whether
    the previous attempt got through."""
    sid = _sid()
    await _submit(sid, _email(), "tok-twice")
    await mark_pending_relink(hash_token("tok-twice"), None, None)

    assert await mark_relinked(sid) is True
    first_verified_at = (await fetch_user(sid))["verified_at"]

    assert await mark_relinked(sid) is True
    assert (await fetch_user(sid))["verified_at"] == first_verified_at


async def test_mark_relinked_returns_false_for_an_unknown_user(cleanup_test_users):
    assert await mark_relinked("test_no_such_user_xyz") is False


async def test_mark_relinked_raises_when_another_account_owns_the_address(
    cleanup_test_users,
):
    """The unique-index conflict moved here with verified.

    idx_foss_users_email is UNIQUE (lower(real_email)) WHERE verified, so this
    UPDATE is now the statement it fires on. Uncaught it would be a 500 in
    whatever runs the relink; the probe in mark_pending_relink is best-effort
    and cannot be relied on, which is why this catch is the enforcement.
    """
    email = _email()
    first, second = _sid(), _sid()
    await _submit(first, email, "tok-w")
    await _submit(second, email, "tok-l")
    await _relink(first, "tok-w")

    # Reach pending_relink without the probe: the loser is in this state
    # whenever the winner relinks *after* they clicked their own link.
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE foss_users SET relink_state = 'pending_relink' "
            "WHERE synthetic_id = $1",
            second,
        )

    with pytest.raises(EmailAlreadyRegistered):
        await mark_relinked(second)

    assert (await fetch_user(second))["verified"] is False
    assert await _state(second) == "pending_relink"


async def test_mark_relinked_completes_a_legacy_verified_row(cleanup_test_users):
    """verified = true with relink_state = 'none' is the legacy combination.
    Completing it is a no-op in substance and must not fail."""
    sid = _sid()
    await _submit(sid, _email(), "tok-legacy")
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE foss_users SET verified = TRUE, verified_at = now() "
            "WHERE synthetic_id = $1",
            sid,
        )

    assert await mark_relinked(sid) is True
    assert await _state(sid) == "relinked"


async def test_next_pending_relink_returns_the_oldest_queued_row(cleanup_test_users):
    """Oldest first, ordered on updated_at rather than insertion order -- a
    tie on now() is possible within one transaction, so the timestamps are set
    explicitly rather than relying on call order."""
    older, newer = _sid(), _sid()
    await _submit(older, _email(), "tok-older")
    await mark_pending_relink(hash_token("tok-older"), None, None)
    await _submit(newer, _email(), "tok-newer")
    await mark_pending_relink(hash_token("tok-newer"), None, None)

    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE foss_users SET updated_at = now() - interval '1 hour' "
            "WHERE synthetic_id = $1",
            older,
        )

    # Defensive against a non-empty queue (a shared or non-fresh database):
    # assert relative ordering rather than that `older` is THE row returned.
    row = await next_pending_relink()
    assert row is not None
    assert row["synthetic_id"] != newer


async def test_next_pending_relink_excludes_verified_rows(cleanup_test_users):
    """The constraint ops_override_write documents: a verified row in
    pending_relink means the address is already live, and relinking app
    accounts onto it would move them to an address they were never keyed to."""
    sid = _sid()
    await _submit(sid, _email(), "tok-verified-pending")
    await mark_pending_relink(hash_token("tok-verified-pending"), None, None)
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE foss_users SET verified = TRUE WHERE synthetic_id = $1", sid
        )

    row = await next_pending_relink()
    assert row is None or row["synthetic_id"] != sid


async def test_mark_relink_failed_sets_both_columns_and_writes_audit(
    cleanup_test_users,
):
    sid = _sid()
    await _submit(sid, _email(), "tok-fail")
    await mark_pending_relink(hash_token("tok-fail"), None, None)

    assert await mark_relink_failed(sid, "collision with test_other_sid") is True

    user = await fetch_user(sid)
    assert user["relink_state"] == "relink_failed"
    assert user["relink_error"] == "collision with test_other_sid"

    pool = await get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT action, user_agent FROM foss_users_audit "
            "WHERE synthetic_id = $1 AND action = 'relink'",
            sid,
        )
    assert len(rows) == 1
    assert "collision with test_other_sid" in rows[0]["user_agent"]


async def test_mark_relink_failed_returns_false_for_an_unknown_user(
    cleanup_test_users,
):
    assert await mark_relink_failed("test_no_such_user_xyz", "whatever") is False


async def test_mark_relinked_clears_relink_error(cleanup_test_users):
    """A stale refusal must not survive a completed relink -- otherwise a user
    who is done reads as failed to anything that looks at the column
    directly."""
    sid = _sid()
    await _submit(sid, _email(), "tok-recover")
    await mark_pending_relink(hash_token("tok-recover"), None, None)
    await mark_relink_failed(sid, "temporary collision")
    assert (await fetch_user(sid))["relink_error"] is not None

    # Re-queue the way an operator or the runner would, then complete it.
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE foss_users SET relink_state = 'pending_relink' "
            "WHERE synthetic_id = $1",
            sid,
        )
    assert await mark_relinked(sid) is True

    user = await fetch_user(sid)
    assert user["relink_state"] == "relinked"
    assert user["relink_error"] is None


async def test_resubmitting_clears_a_pending_relink(cleanup_test_users):
    """A fresh submission starts the flow over, so it must not leave the row
    claiming a relink is in flight for an address that has just changed."""
    sid = _sid()
    await _submit(sid, _email(), "tok-a")
    await mark_pending_relink(hash_token("tok-a"), None, None)
    assert await _state(sid) == "pending_relink"

    await _submit(sid, _email(), "tok-b")

    assert await _state(sid) == "none"


async def test_rotate_verification_token_returns_the_recipient(cleanup_test_users):
    sid, email = _sid(), _email()
    await _submit(sid, email, "old_token", display_name="Jane")

    result = await rotate_verification_token(
        sid, hash_token("new_token"), _in_a_day(), None, None
    )

    assert result == {"real_email": email, "display_name": "Jane"}
    assert (await fetch_user(sid))["verification_token"] == hash_token("new_token")


async def test_rotate_verification_token_raises_for_a_missing_row(cleanup_test_users):
    with pytest.raises(NoSubmissionYet):
        await rotate_verification_token(
            _sid(), hash_token("tok"), _in_a_day(), None, None
        )


async def test_rotate_verification_token_raises_for_a_verified_row(cleanup_test_users):
    sid = _sid()
    await _submit(sid, _email(), "tok-done")
    await _relink(sid, "tok-done")

    with pytest.raises(AlreadyVerified):
        await rotate_verification_token(
            sid, hash_token("tok-new"), _in_a_day(), None, None
        )


async def test_insert_audit_records_row(cleanup_test_users):
    sid = _sid()
    await insert_audit(
        synthetic_id=sid,
        action="dismiss_modal",
        email=None,
        consent_text_version=None,
        consent_text_content=None,
        ip_address="127.0.0.1",
        user_agent="pytest",
    )

    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM foss_users_audit WHERE synthetic_id = $1", sid
        )
    assert row is not None
    assert row["action"] == "dismiss_modal"


async def test_audit_table_is_append_only_for_the_api_role(cleanup_test_users):
    """launchpad_api_user may INSERT into foss_users_audit but not DELETE.

    The table is an immutable action history -- it deliberately has no FK to
    foss_users so rows outlive the users they describe -- and nothing in db.py
    deletes from it. Holding DELETE bought nothing and meant a compromised
    launchpad-api could erase the consent record this feature exists to produce.

    Asserting the INSERT half matters as much as the DELETE half: a revoke that
    over-reached would break every audit write, and the service swallows some of
    those failures.
    """
    sid = _sid()
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO foss_users_audit (synthetic_id, action) VALUES ($1, 'submit_email')",
            sid,
        )
        assert await conn.fetchval(
            "SELECT count(*) FROM foss_users_audit WHERE synthetic_id = $1", sid
        ) == 1

        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute(
                "DELETE FROM foss_users_audit WHERE synthetic_id = $1", sid
            )


async def test_mark_relinked_refuses_a_user_who_never_verified(cleanup_test_users):
    """The guard that stops mark_relinked being mark_verified in disguise.

    A user who submits an address and never opens the mail sits at
    ('none', verified=FALSE). Without the state guard, any caller handed that
    sid -- a runner iterating the wrong predicate, an operator working from a
    stale list -- would publish an unproven address to all five apps. The
    partial index cannot help: nobody verified it, so there is nothing to
    collide with.
    """
    sid = f"test_{secrets.token_hex(4)}"
    await submit_email(
        synthetic_id=sid, email="unproven@corp.example", display_name=None,
        token_hash=hash_token("tok_" + sid),
        verification_expires=datetime.now(timezone.utc) + timedelta(hours=24),
        consent_text_version="t", consent_text_content="t",
        ip_address=None, user_agent=None,
    )

    assert await mark_relinked(sid) is False

    user = await fetch_user(sid)
    assert user["verified"] is False
    assert user["relink_state"] == "none"

    # The overlay must still find nothing for them.
    pool = await get_pool()
    async with pool.acquire() as conn:
        assert await conn.fetchval(
            "SELECT real_email FROM foss_users WHERE synthetic_id = $1 AND verified = TRUE",
            sid,
        ) is None

