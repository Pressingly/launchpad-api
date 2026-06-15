"""Postgres connection pool and queries for launchpad-api."""
from datetime import datetime, timedelta, timezone
from typing import Optional

import asyncpg

from src.config import settings


_pool: Optional[asyncpg.Pool] = None


async def get_pool() -> asyncpg.Pool:
    """Lazy-initialize the asyncpg connection pool."""
    global _pool
    if _pool is None:
        _pool = await asyncpg.create_pool(
            dsn=settings.db_dsn,
            min_size=2,
            max_size=10,
            command_timeout=10,
        )
    return _pool


async def close_pool() -> None:
    """Close the pool — used in tests."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


async def fetch_user(synthetic_id: str) -> Optional[dict]:
    """Fetch a foss_users row by synthetic_id. Returns None if not found."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT synthetic_id, real_email, display_name, verified,
                   verification_token, verification_expires,
                   verified_at, created_at, updated_at
            FROM foss_users WHERE synthetic_id = $1
            """,
            synthetic_id,
        )
    return dict(row) if row else None


async def insert_user(
    synthetic_id: str,
    email: str,
    display_name: Optional[str],
    verification_token: str,
    verification_expires: datetime,
) -> None:
    """Insert a new (unverified) foss_users row, or update if it already exists."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO foss_users (
                synthetic_id, real_email, display_name,
                verification_token, verification_expires,
                verified, updated_at
            ) VALUES ($1, $2, $3, $4, $5, FALSE, now())
            ON CONFLICT (synthetic_id) DO UPDATE
            SET real_email = EXCLUDED.real_email,
                display_name = EXCLUDED.display_name,
                verification_token = EXCLUDED.verification_token,
                verification_expires = EXCLUDED.verification_expires,
                verified = FALSE,
                updated_at = now()
            """,
            synthetic_id, email, display_name,
            verification_token, verification_expires,
        )


async def mark_verified(token: str) -> Optional[str]:
    """Mark a row as verified by token. Returns synthetic_id if successful, None if invalid/expired."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            UPDATE foss_users
            SET verified = TRUE,
                verification_token = NULL,
                verification_expires = NULL,
                verified_at = now(),
                updated_at = now()
            WHERE verification_token = $1
              AND verification_expires > now()
            RETURNING synthetic_id
            """,
            token,
        )
    return row["synthetic_id"] if row else None


async def rotate_verification_token(
    synthetic_id: str,
    new_token: str,
    new_expires: datetime,
) -> bool:
    """Generate a new verification token for an existing unverified row.
    Returns True if updated, False if row doesn't exist or is already verified."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        result = await conn.execute(
            """
            UPDATE foss_users
            SET verification_token = $2,
                verification_expires = $3,
                updated_at = now()
            WHERE synthetic_id = $1 AND verified = FALSE
            """,
            synthetic_id, new_token, new_expires,
        )
    return result.endswith("1")


async def insert_audit(
    synthetic_id: str,
    action: str,
    email: Optional[str],
    consent_text_version: Optional[str],
    consent_text_content: Optional[str],
    ip_address: Optional[str],
    user_agent: Optional[str],
) -> None:
    """Insert an audit row. Always succeeds (or raises)."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO foss_users_audit (
                synthetic_id, action, email,
                consent_text_version, consent_text_content,
                ip_address, user_agent
            ) VALUES ($1, $2, $3, $4, $5, $6::inet, $7)
            """,
            synthetic_id, action, email,
            consent_text_version, consent_text_content,
            ip_address, user_agent,
        )
