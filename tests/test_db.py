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
    mark_verified,
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
    assert await mark_verified(hash_token("tok-verify"), None, None) == sid

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
    await mark_verified(hash_token("tok-victim"), None, None)

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


async def test_mark_verified_with_valid_token(cleanup_test_users):
    sid = _sid()
    await _submit(sid, _email(), "good_token")

    assert await mark_verified(hash_token("good_token"), None, None) == sid

    user = await fetch_user(sid)
    assert user["verified"] is True
    assert user["verification_token"] is None


async def test_mark_verified_writes_the_verify_email_audit_row(cleanup_test_users):
    sid = _sid()
    await _submit(sid, _email(), "audited_token")
    await mark_verified(hash_token("audited_token"), "203.0.113.4", "pytest")

    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT ip_address, user_agent FROM foss_users_audit "
            "WHERE synthetic_id = $1 AND action = 'verify_email'",
            sid,
        )
    assert row is not None
    assert str(row["ip_address"]) == "203.0.113.4"


async def test_mark_verified_with_expired_token(cleanup_test_users):
    sid = _sid()
    expired = datetime.now(timezone.utc) - timedelta(hours=1)
    await _submit(sid, _email(), "expired_token", expires=expired)

    assert await mark_verified(hash_token("expired_token"), None, None) is None


async def test_mark_verified_rejects_the_raw_token_lookalike(cleanup_test_users):
    """The column holds a digest, so passing the raw value finds nothing."""
    sid = _sid()
    await _submit(sid, _email(), "raw_token")

    assert await mark_verified("raw_token", None, None) is None
    assert (await fetch_user(sid))["verified"] is False


async def test_mark_verified_raises_when_another_account_owns_the_address(
    cleanup_test_users,
):
    email = _email()
    first, second = _sid(), _sid()
    await _submit(first, email, "tok-first")
    await _submit(second, email, "tok-second")
    await mark_verified(hash_token("tok-first"), None, None)

    with pytest.raises(EmailAlreadyRegistered):
        await mark_verified(hash_token("tok-second"), None, None)

    assert (await fetch_user(second))["verified"] is False


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
    await mark_verified(hash_token("tok-done"), None, None)

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
