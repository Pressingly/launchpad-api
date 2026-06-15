"""Tests for the database connection layer."""
import secrets
from datetime import datetime, timedelta, timezone

import pytest

from src.db import (
    close_pool,
    fetch_user,
    get_pool,
    insert_audit,
    insert_user,
    mark_verified,
    rotate_verification_token,
)


@pytest.fixture(autouse=True)
async def _reset_pool_per_test():
    """Pytest-asyncio creates a fresh event loop per test, so we must close
    and recreate the asyncpg pool for each one — otherwise the pool's
    connections are tied to a dead loop."""
    yield
    await close_pool()


@pytest.mark.asyncio
async def test_pool_can_query():
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.fetchval("SELECT 1")
    assert result == 1


@pytest.fixture
async def cleanup_test_users():
    """After each test, delete any rows created for test synthetic_ids."""
    yield
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM foss_users WHERE synthetic_id LIKE 'test_%'")
        await conn.execute("DELETE FROM foss_users_audit WHERE synthetic_id LIKE 'test_%'")


@pytest.mark.asyncio
async def test_insert_and_fetch_user(cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    await insert_user(sid, "test@example.com", "Test User", "tok123", expires)

    user = await fetch_user(sid)
    assert user is not None
    assert user["real_email"] == "test@example.com"
    assert user["display_name"] == "Test User"
    assert user["verified"] is False
    assert user["verification_token"] == "tok123"


@pytest.mark.asyncio
async def test_fetch_user_not_found(cleanup_test_users):
    result = await fetch_user("test_nonexistent_xyz")
    assert result is None


@pytest.mark.asyncio
async def test_mark_verified_with_valid_token(cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    await insert_user(sid, "test@example.com", None, "good_token", expires)

    result = await mark_verified("good_token")
    assert result == sid

    user = await fetch_user(sid)
    assert user["verified"] is True
    assert user["verification_token"] is None


@pytest.mark.asyncio
async def test_mark_verified_with_expired_token(cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    expires = datetime.now(timezone.utc) - timedelta(hours=1)  # already expired
    await insert_user(sid, "test@example.com", None, "expired_token", expires)

    result = await mark_verified("expired_token")
    assert result is None  # expired


@pytest.mark.asyncio
async def test_insert_audit_records_row(cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    await insert_audit(
        synthetic_id=sid,
        action="submit_email",
        email="test@example.com",
        consent_text_version="v1.0",
        consent_text_content="I consent",
        ip_address="127.0.0.1",
        user_agent="pytest",
    )

    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM foss_users_audit WHERE synthetic_id = $1", sid
        )
    assert row is not None
    assert row["action"] == "submit_email"
    assert row["email"] == "test@example.com"
