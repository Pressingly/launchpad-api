"""Postgres connection pool and queries for launchpad-api."""
import hashlib
from datetime import datetime
from typing import Optional

import asyncpg

from src.config import settings


def hash_token(raw_token: str) -> str:
    """sha256 hex of a verification token.

    The database stores this, never the raw value that goes in the email link.
    Anything that can read the column (a dump, a backup, leaked read-only
    credentials) therefore cannot replay it.

    No salt and no HMAC, deliberately. A per-row salt would make lookup
    impossible -- you cannot find the row without already knowing which row's
    salt to use. That is safe here because a salt's job is defeating
    precomputation against low-entropy input, and the input is
    secrets.token_urlsafe(32): 256 bits. A bare sha256 of 256 random bits has no
    rainbow table.
    """
    return hashlib.sha256(raw_token.encode()).hexdigest()


class EmailAlreadyRegistered(Exception):
    """A real_email is already verified by a *different* synthetic_id.

    Since the unique index on real_email became partial (WHERE verified), this
    no longer fires when an address is *claimed* -- unverified claims are not
    binding and never collide. It fires only when a second account tries to
    *verify* an address someone else has already verified, i.e. from
    mark_verified rather than from the submit path.
    """

    def __init__(self, email: str = ""):
        self.email = email
        super().__init__(f"email already verified by another account: {email}")


class AlreadyVerified(Exception):
    """The caller's own row is already verified.

    Distinct from EmailAlreadyRegistered: this is about the caller's own state,
    not somebody else's, so surfacing it to them leaks nothing.
    """


class NoSubmissionYet(Exception):
    """The caller has no foss_users row to act on."""


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


async def _insert_audit(
    conn: asyncpg.Connection,
    synthetic_id: str,
    action: str,
    email: Optional[str],
    consent_text_version: Optional[str],
    consent_text_content: Optional[str],
    ip_address: Optional[str],
    user_agent: Optional[str],
) -> None:
    """Audit insert on a caller-supplied connection, so it can share a
    transaction with the write it records."""
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


async def insert_audit(
    synthetic_id: str,
    action: str,
    email: Optional[str],
    consent_text_version: Optional[str],
    consent_text_content: Optional[str],
    ip_address: Optional[str],
    user_agent: Optional[str],
) -> None:
    """Standalone audit insert, for actions with no accompanying write."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        await _insert_audit(
            conn, synthetic_id, action, email,
            consent_text_version, consent_text_content,
            ip_address, user_agent,
        )


async def submit_email(
    synthetic_id: str,
    email: str,
    display_name: Optional[str],
    token_hash: str,
    verification_expires: datetime,
    consent_text_version: str,
    consent_text_content: str,
    ip_address: Optional[str],
    user_agent: Optional[str],
) -> bool:
    """Record an email submission and its consent, atomically.

    Returns True when the address is already verified by a different account,
    so the caller can decline to send: that mail could only ever reach someone
    who did not ask for it, and its link could never be used anyway (the
    recipient's own verification would hit the partial index).

    The row write and the audit write share one transaction. Previously they
    took separate connections, so a failure between them left the platform
    holding a personal email address with no record that the user agreed to it
    -- the exact inverse of what this feature exists to produce.

    Raises AlreadyVerified when the caller's row is already verified.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            # The ON CONFLICT branch is constrained to unverified rows, so a
            # verified caller is skipped rather than reset. Verified against
            # PostgreSQL 17: a skipped conflict yields INSERT 0 0 and RETURNING
            # produces zero rows, while both the insert and the update branches
            # always return one. There is no ambiguous third case -- an insert
            # failing for any other reason raises. So None means exactly
            # "exists and is already verified", with no second query and no
            # read-then-write race.
            row = await conn.fetchrow(
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
                WHERE foss_users.verified = FALSE
                RETURNING synthetic_id
                """,
                synthetic_id, email, display_name,
                token_hash, verification_expires,
            )
            if row is None:
                raise AlreadyVerified()

            # Is this address already verified by somebody else? Best-effort:
            # a SELECT under READ COMMITTED, so a concurrent verification can
            # commit between this and the audit write and the collision is
            # missed. Deliberately not FOR SHARE -- the partial index is the
            # enforcement, this is only observability, and a missed audit row
            # under a race costs far less than lock contention on the identity
            # table's hot path.
            # lower(): the unique index is on lower(real_email) because
            # EmailStr normalises only the domain, so Alice.B@example.com and
            # alice.b@example.com are distinct strings that almost every mail
            # provider treats as one mailbox. Left case-sensitive, the same
            # human signing up once with autocapitalised input and once without
            # becomes two verified principals across all five apps -- the
            # orphaning this whole change exists to prevent. The probe must
            # match the index or it misses the same cases.
            collision = await conn.fetchval(
                """
                SELECT TRUE FROM foss_users
                WHERE lower(real_email) = lower($1)
                  AND verified = TRUE AND synthetic_id <> $2
                LIMIT 1
                """,
                email, synthetic_id,
            )

            # A collision row *replaces* the submit_email row rather than
            # supplementing it. foss_users_audit is the compliance artifact and
            # a submit_email row means "this person consented to receive mail
            # here" -- a probe is not that. Writing both would permanently
            # record prober -> victim address as a consent event.
            await _insert_audit(
                conn,
                synthetic_id=synthetic_id,
                action="submit_email_collision" if collision else "submit_email",
                email=email,
                consent_text_version=consent_text_version,
                consent_text_content=consent_text_content,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            return bool(collision)


async def mark_verified(
    token_hash: str,
    ip_address: Optional[str],
    user_agent: Optional[str],
) -> Optional[str]:
    """Verify by token hash. Returns synthetic_id, or None if the token is
    invalid or expired.

    Raises EmailAlreadyRegistered when the address has already been verified by
    a different account. That conflict used to surface at submit time; making
    the unique index partial moved it here, and this function previously had no
    exception handling at all, so it would have been an uncaught 500 for a user
    clicking a legitimate link.

    The audit write shares the transaction, for the same reason as submit_email.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            try:
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
                    RETURNING synthetic_id, real_email
                    """,
                    token_hash,
                )
            except asyncpg.UniqueViolationError as exc:
                # Only the address index means "someone else has this address".
                # Any other unique violation is a different bug and must not be
                # reported to the user as an address conflict -- today there is
                # no other unique constraint on foss_users, but a future one
                # (a unique index on verification_token is the obvious
                # candidate) would otherwise silently redirect a legitimate user
                # to a message telling them to contact an administrator.
                if exc.constraint_name != "idx_foss_users_email":
                    raise
                raise EmailAlreadyRegistered() from exc

            if row is None:
                return None

            await _insert_audit(
                conn,
                synthetic_id=row["synthetic_id"],
                action="verify_email",
                email=None,
                consent_text_version=None,
                consent_text_content=None,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            return row["synthetic_id"]


async def rotate_verification_token(
    synthetic_id: str,
    token_hash: str,
    verification_expires: datetime,
    ip_address: Optional[str],
    user_agent: Optional[str],
) -> dict:
    """Issue a fresh verification token for an unverified row.

    Returns {"real_email", "display_name"} on success.
    Raises NoSubmissionYet or AlreadyVerified.

    One statement decides eligibility and rotates. The previous shape was
    fetch -> check -> update across three separate connections, so two
    near-simultaneous resends both passed the check and both rotated: the user
    got two emails and the first link was already dead, with nothing indicating
    which was which. The CTE below reads the row's state and performs the update
    in the same snapshot, so the check cannot go stale between the two.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                WITH target AS (
                    SELECT synthetic_id, verified FROM foss_users
                     WHERE synthetic_id = $1
                ), upd AS (
                    UPDATE foss_users
                       SET verification_token = $2,
                           verification_expires = $3,
                           updated_at = now()
                     WHERE synthetic_id = $1 AND verified = FALSE
                    RETURNING real_email, display_name
                )
                SELECT (SELECT count(*) FROM target)      AS row_exists,
                       (SELECT verified FROM target)      AS was_verified,
                       (SELECT real_email FROM upd)       AS real_email,
                       (SELECT display_name FROM upd)     AS display_name
                """,
                synthetic_id, token_hash, verification_expires,
            )

            if not row["row_exists"]:
                raise NoSubmissionYet()
            # `target` is read from the statement snapshot but `upd` re-evaluates
            # verified = FALSE against the latest row version after taking the
            # row lock. So a verification committing between the two leaves
            # was_verified FALSE while the UPDATE matches nothing. real_email is
            # NOT NULL in the schema, so a NULL here means exactly that: the
            # update was skipped. Without this the caller got 200 {"status":"ok"},
            # a spurious resend_verification row in the compliance table, and no
            # email -- because the send then failed on a None address and was
            # swallowed.
            if row["was_verified"] or row["real_email"] is None:
                raise AlreadyVerified()

            await _insert_audit(
                conn,
                synthetic_id=synthetic_id,
                action="resend_verification",
                email=row["real_email"],
                consent_text_version=None,
                consent_text_content=None,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            return {
                "real_email": row["real_email"],
                "display_name": row["display_name"],
            }
