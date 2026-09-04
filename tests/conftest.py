"""Pytest fixtures for launchpad-api tests."""
import hashlib
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import asyncpg
import httpx
import pytest
from httpx import AsyncClient, ASGITransport

from src import consent_text, db
from src.config import settings
from src.main import app

MAILPIT_BASE = "http://mailpit:8025"

# Superuser DSN, used only by tests that must change schema or grants (the
# atomicity and migration cases). PRD §7's run command does not pass admin
# credentials, so we default to the documented local harness values.
TEST_ADMIN_DSN = os.environ.get(
    "TEST_ADMIN_DSN",
    f"postgresql://postgres:pw@{settings.db_host}:{settings.db_port}/{settings.db_name}",
)


# ---------------------------------------------------------------------------
# Core fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
async def _reset_pool_per_test():
    """Pytest-asyncio creates a fresh event loop per test, so we must close
    and recreate the asyncpg pool for each one — otherwise the pool's
    connections are tied to a dead loop."""
    yield
    await db.close_pool()


@pytest.fixture(autouse=True)
async def _reset_rate_limiter():
    """Clear the limiter keyspace before *and* after every test.

    Before matters as much as after. The module-level Redis client has the
    same event-loop problem as the asyncpg pool — its pooled connections bind
    to the loop that opened them, and pytest-asyncio gives every test a fresh
    loop — so `_reset_for_tests()` drops the pool as its first act. Skipping
    the setup call makes the second test in a run raise "Event loop is closed"
    *inside* `check_and_increment`, where the fail-open handler swallows it and
    every limit silently stops counting: the rate-limit tests would then pass
    while testing nothing.

    `src.rate_limit` may not exist yet (lane 2 owns it), so the import is
    guarded — a missing module must not break the whole suite.
    """
    try:
        from src import rate_limit
    except ImportError:
        yield
        return

    async def _reset():
        # Deliberately *not* wrapped in try/except: lane 2 states that a reset
        # which silently fails produces confusing cross-test bleed, and Valkey
        # is required infrastructure for this suite (PRD §7). A limiter outage
        # should surface here, not as nine bare `202 != 429` failures later.
        await rate_limit._reset_for_tests()

    await _reset()
    yield
    await _reset()


@pytest.fixture
async def client():
    """An AsyncClient for hitting the FastAPI app in-process."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def raw_client():
    """Like `client`, but unhandled exceptions inside the app become 500
    responses instead of propagating into the test.

    Every "must not 500" assertion needs this: with the default transport an
    uncaught UniqueViolationError surfaces as a traceback in the test body, so
    the test errors out instead of failing on a status-code assertion.
    """
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def cleanup_test_users():
    """After each test, delete any rows created for test synthetic_ids."""
    yield
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM foss_users WHERE synthetic_id LIKE 'test_%'")
        await conn.execute("DELETE FROM foss_users_audit WHERE synthetic_id LIKE 'test_%'")


# ---------------------------------------------------------------------------
# Valkey-down fixture (PRD §4.6 fail-open, §7b interface)
# ---------------------------------------------------------------------------


class _DeadRedis:
    """Stands in for an unreachable Valkey.

    Every attribute access yields a callable that raises synchronously, so
    `_client.incr(...)`, `_client.pipeline()` and `async with
    _client.pipeline()` all blow up before any await — whatever call shape
    lane 2 chose.
    """

    def _boom(self, *args, **kwargs):
        raise _CONNECTION_ERROR("valkey is unreachable (simulated outage)")

    def __getattr__(self, name):
        return self._boom

    def __call__(self, *args, **kwargs):
        self._boom()

    async def __aenter__(self):
        self._boom()

    async def __aexit__(self, *exc):
        return False


try:  # pragma: no cover - depends on whether redis is installed yet
    from redis.exceptions import ConnectionError as _CONNECTION_ERROR
except ImportError:  # pragma: no cover
    _CONNECTION_ERROR = ConnectionError


@pytest.fixture
def valkey_down(monkeypatch):
    """Simulate a Valkey outage by replacing the limiter's module-level client.

    Named in the PRD §7b interface precisely so this fixture can exist before
    lane 2 does. If the module does not exist yet there is nothing to throttle,
    so this is a no-op — tests that specifically assert fail-open import
    `src.rate_limit` themselves and fail loudly instead.
    """
    try:
        from src import rate_limit
    except ImportError:
        return None

    monkeypatch.setattr(rate_limit, "_client", _DeadRedis())
    return rate_limit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def new_sid() -> str:
    return f"test_{secrets.token_hex(4)}"


def new_email(prefix: str = "u") -> str:
    """Unique per call: real_email is uniquely indexed for verified rows, so a
    fixed address would be permanently claimed against a persistent database."""
    return f"{prefix}-{secrets.token_hex(6)}@example.com"


def sha256_hex(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def submit_payload(email: str, display_name: Optional[str] = None) -> dict:
    return {
        "email": email,
        "display_name": display_name,
        "consent": True,
        "consent_text_version": consent_text.CURRENT_VERSION,
    }


async def submit(ac: AsyncClient, sid: str, email: str, display_name=None, version=None):
    """POST /api/email as `sid`."""
    payload = submit_payload(email, display_name)
    if version is not None:
        payload["consent_text_version"] = version
    return await ac.post(
        "/api/email",
        headers={"X-Auth-Request-Preferred-Username": sid},
        json=payload,
    )


async def seed_pending(
    sid: str,
    email: str,
    raw_token: str,
    expires: Optional[datetime] = None,
) -> None:
    """Insert an unverified row directly, storing sha256(raw_token).

    Deliberately bypasses `db.insert_user`: the PRD fixes *what the column
    holds* (§1.2) but not which layer does the hashing, so seeding through the
    db layer would couple these tests to lane 4's factoring.
    """
    if expires is None:
        expires = datetime.now(timezone.utc) + timedelta(hours=24)
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO foss_users (
                synthetic_id, real_email, display_name,
                verification_token, verification_expires, verified, updated_at
            ) VALUES ($1, $2, $3, $4, $5, FALSE, now())
            ON CONFLICT (synthetic_id) DO UPDATE
            SET real_email = EXCLUDED.real_email,
                display_name = EXCLUDED.display_name,
                verification_token = EXCLUDED.verification_token,
                verification_expires = EXCLUDED.verification_expires,
                verified = FALSE,
                updated_at = now()
            """,
            sid, email, None, sha256_hex(raw_token), expires,
        )


async def audit_actions(sid: str) -> list:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT action FROM foss_users_audit WHERE synthetic_id = $1 ORDER BY id",
            sid,
        )
    return [r["action"] for r in rows]


async def row_counts() -> dict:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        users = await conn.fetchval("SELECT count(*) FROM foss_users")
        audit = await conn.fetchval("SELECT count(*) FROM foss_users_audit")
    return {"foss_users": users, "foss_users_audit": audit}


# ---------------------------------------------------------------------------
# Mailpit helpers
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"token=([A-Za-z0-9_\-]+)")


async def mailpit_clear() -> None:
    async with httpx.AsyncClient() as ac:
        await ac.delete(f"{MAILPIT_BASE}/api/v1/messages")


async def mailpit_messages() -> list:
    """Messages, newest first (mailpit's own ordering)."""
    async with httpx.AsyncClient() as ac:
        resp = await ac.get(f"{MAILPIT_BASE}/api/v1/messages?limit=50")
    return resp.json().get("messages", [])


async def mailpit_token(message_id: str) -> str:
    """Pull the verification token out of one message's plain-text body."""
    async with httpx.AsyncClient() as ac:
        resp = await ac.get(f"{MAILPIT_BASE}/api/v1/message/{message_id}")
    body = resp.json()
    text = (body.get("Text") or "") + (body.get("HTML") or "")
    match = _TOKEN_RE.search(text)
    assert match, f"no verification token found in message {message_id}"
    return match.group(1)


async def latest_token() -> str:
    messages = await mailpit_messages()
    assert messages, "mailpit received no messages"
    return await mailpit_token(messages[0]["ID"])


@pytest.fixture
async def clean_mailbox():
    """Empty the mailpit inbox before the test so message ordering is
    unambiguous."""
    await mailpit_clear()
    yield


# ---------------------------------------------------------------------------
# Admin (superuser) connection — schema/grant manipulation only
# ---------------------------------------------------------------------------


@pytest.fixture
async def admin_conn():
    conn = await asyncpg.connect(TEST_ADMIN_DSN)
    try:
        yield conn
    finally:
        await conn.close()
