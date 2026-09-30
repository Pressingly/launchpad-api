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
    binding and never collide. It fires when a second account tries to take an
    address someone else has already verified, never from the submit path.

    It has two raise sites, and both are load-bearing. The index fires on the
    UPDATE that sets verified, which is now mark_relinked -- so mark_relinked is
    where the conflict is actually *enforced*. mark_pending_relink raises it too,
    from an explicit probe: catching it at click time is better UX than letting
    the user sit in pending_relink until an operator tries to complete them, it
    is just no longer sufficient on its own.
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


class AuditVocabularyMissing(Exception):
    """foss_users_audit's CHECK does not accept 'ops_override' yet.

    A schema gap, not a data conflict: the audit-vocabulary widening is a
    separate runbook step from the relink_state block, so an upgrader can apply
    one without the other. Raised so the ops override can report it as a
    refusal with a fix, rather than as a raw Postgres traceback.
    """


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
                   relink_state, relink_error,
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

    A pending_relink caller IS accepted, and the upsert resets relink_state to
    'none'. That is deliberate -- the relink target just changed, so a marker
    saying one is in flight to the old address would be false. The UI offers no
    resubmit control in that state, so this is the API being more permissive
    than the portal rather than a route users are pointed at.

    It does leave a gap for part 2: under LAUNCHPAD_RELINK_RUNNER=manual an
    operator may already have moved some app accounts to the old address when
    the user resubmits, and nothing records that. The manual path needs a
    reconciliation step; the runner path does not, because it reads
    relink_state and will simply not find them queued.
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
                    -- A fresh submission starts the flow over, so it must not
                    -- leave the row in pending_relink: that state means "this
                    -- address is being relinked", and the address has just
                    -- changed. Only unverified rows reach this branch, so a
                    -- relinked user is never reset -- verified = FALSE with
                    -- relink_state = 'pending_relink' is the only combination
                    -- this can overwrite.
                    relink_state = 'none',
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
            _collision = bool(collision)

    # Outside the transaction, so the memo is never dropped for a write that
    # then rolls back. The ON CONFLICT above resets relink_state from
    # 'pending_relink' to 'none', and the memo carries relink_state as well as
    # the address -- so a user who corrects their address while held at
    # RELINKING would keep being held for up to the TTL instead of being sent
    # back to COLLECT.
    #
    # That direction is fail-closed (held, not released) and /api/me reads the
    # database directly, so the portal panel is already correct. Evicting anyway
    # because gate.evict's contract is unconditional: every transition that
    # changes a memoized field evicts. The next transition added may not be
    # fail-closed, and the invariant is only useful if it has no exceptions.
    #
    # Imported locally, like the other two evict sites: src.gate imports src.db,
    # so a module-level import here is circular.
    from src import gate as _gate
    _gate.evict(synthetic_id)
    return _collision


_CONSUME_TOKEN_HOLD = """
    UPDATE foss_users
    SET relink_state = 'pending_relink',
        verification_token = NULL,
        verification_expires = NULL,
        updated_at = now()
    WHERE verification_token = $1
      AND verification_expires > now()
    RETURNING synthetic_id, real_email
"""

# RELINK_SKIP only. The token check stands in for mark_relinked's state guard:
# the row is completed only by the click that proves control of the address.
_CONSUME_TOKEN_COMPLETE = """
    UPDATE foss_users
    SET verified = TRUE,
        relink_state = 'relinked',
        relink_error = NULL,
        verification_token = NULL,
        verification_expires = NULL,
        verified_at = COALESCE(verified_at, now()),
        updated_at = now()
    WHERE verification_token = $1
      AND verification_expires > now()
    RETURNING synthetic_id, real_email
"""


async def _address_taken(conn: asyncpg.Connection, email: str, synthetic_id: str) -> bool:
    # lower(), matching idx_foss_users_email, for the reason spelled out in
    # submit_email: EmailStr normalises only the domain, so a case-sensitive
    # probe misses exactly the duplicates that index exists to catch.
    return bool(await conn.fetchval(
        """
        SELECT TRUE FROM foss_users
        WHERE lower(real_email) = lower($1)
          AND verified = TRUE AND synthetic_id <> $2
        LIMIT 1
        """,
        email, synthetic_id,
    ))


async def _consume_verification_token(
    update_sql: str,
    token_hash: str,
    ip_address: Optional[str],
    user_agent: Optional[str],
) -> Optional[str]:
    """Consume the token, refuse a taken address and write the audit row, all in
    one transaction. Any refusal rolls the token consumption back, so the user
    keeps a link that still works and is never stranded token-less."""
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            try:
                row = await conn.fetchrow(update_sql, token_hash)
            except asyncpg.UniqueViolationError as exc:
                # Only reachable when completing: the probe below lost a race
                # and the verified-address index fired on this UPDATE.
                if exc.constraint_name != "idx_foss_users_email":
                    raise
                raise EmailAlreadyRegistered() from exc

            if row is None:
                return None

            if await _address_taken(conn, row["real_email"], row["synthetic_id"]):
                raise EmailAlreadyRegistered(row["real_email"])

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


async def mark_pending_relink(
    token_hash: str,
    ip_address: Optional[str],
    user_agent: Optional[str],
) -> Optional[str]:
    """Consume a verification token. Returns synthetic_id, or None if the token
    is invalid or expired.

    This is what /api/verify calls, and it deliberately does NOT set verified.
    The mpass overlay reads `WHERE verified = TRUE`, so flipping it here would
    hand the real address to all five apps before their accounts have been
    relinked -- each app would then create a second account and strand the
    user's existing content. That is the whole point of the state machine:
    clicking the link moves the user to pending_relink, and only the relink
    itself (mark_relinked) sets verified.

    Raises EmailAlreadyRegistered when the address is already verified by a
    different account. Because verified is no longer set here, the partial
    unique index cannot fire on this statement, so the check is an explicit
    probe rather than a caught UniqueViolationError. It is best-effort under
    READ COMMITTED -- the index remains the enforcement, at mark_relinked --
    but telling the user at click time is far better than letting them wait in
    pending_relink for a relink that can never complete.

    The audit write shares the transaction, for the same reason as submit_email.
    """
    return await _consume_verification_token(
        _CONSUME_TOKEN_HOLD, token_hash, ip_address, user_agent
    )


async def verify_and_complete(
    token_hash: str,
    ip_address: Optional[str],
    user_agent: Optional[str],
) -> Optional[str]:
    """RELINK_SKIP: consume the token and complete the user in one transaction.

    The second place verified becomes true, and only for installs that declared
    there is nothing to relink (LAUNCHPAD_RELINK_RUNNER=skip). Everywhere else
    mark_relinked stays the only one. One transaction, so a failure part-way
    leaves the user with their token and never token-less in pending_relink,
    which nothing would ever complete under skip.

    Returns synthetic_id, or None when the token is invalid or expired. Raises
    EmailAlreadyRegistered when another account has verified the address.
    """
    synthetic_id = await _consume_verification_token(
        _CONSUME_TOKEN_COMPLETE, token_hash, ip_address, user_agent
    )
    if synthetic_id is not None:
        from src import gate as _gate
        _gate.evict(synthetic_id)
    return synthetic_id


async def mark_relinked(synthetic_id: str) -> bool:
    """Complete the relink: set verified = TRUE and relink_state = 'relinked'.

    Returns False when there is no such row. Idempotent: re-running it on an
    already-relinked user succeeds and changes nothing observable (verified_at
    keeps its original value), so an operator or a runner can retry without
    having to know whether the previous attempt got through.

    **This is the only place verified becomes true**, except verify_and_complete
    under LAUNCHPAD_RELINK_RUNNER=skip, where there is nothing to relink.
    mark_verified used to do it from /api/verify; it is deleted rather than kept as an alias precisely
    because a caller that sets verified without relinking recreates the
    duplicate-account bug this state machine exists to prevent.

    Raises EmailAlreadyRegistered when a different account has already verified
    the address. The conflict moved here with verified: idx_foss_users_email is
    UNIQUE (lower(real_email)) WHERE verified, so this UPDATE is now the
    statement it fires on. Uncaught it would be a 500 in whatever runs the
    relink; mark_pending_relink's earlier probe is best-effort and cannot be
    relied on, so this catch is the enforcement point.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            try:
                row = await conn.fetchrow(
                    """
                    UPDATE foss_users
                    SET verified = TRUE,
                        relink_state = 'relinked',
                        -- Cleared unconditionally. A prior refusal recorded here
                        -- is now stale the moment the relink completes -- by any
                        -- path, including a retry after the runner or an
                        -- operator resolved the collision -- and a lingering
                        -- value would misreport a completed user as failed to
                        -- anything that reads the column directly.
                        relink_error = NULL,
                        verification_token = NULL,
                        verification_expires = NULL,
                        verified_at = COALESCE(verified_at, now()),
                        updated_at = now()
                    WHERE synthetic_id = $1
                      -- The state guard is the point. Without it this is
                      -- mark_verified with the token check removed: it would
                      -- set `verified` on a row that never proved control of
                      -- the address. A user who submits victim@corp.com and
                      -- never opens the mail sits at ('none', FALSE); a runner
                      -- iterating the wrong predicate, or an operator working
                      -- from a stale list, would then publish that address to
                      -- all five apps. The partial index cannot stop it --
                      -- nobody has verified the address, so there is nothing
                      -- to collide with. 'relinked' is admitted so the
                      -- documented idempotency still holds.
                      -- Refuses exactly one state: ('none', verified=FALSE),
                      -- the user who submitted an address and never opened the
                      -- mail. Admits pending_relink (the ordinary path),
                      -- relinked (documented idempotency) and the legacy
                      -- ('none', verified=TRUE) row, which is already complete.
                      AND (relink_state <> 'none' OR verified)
                    RETURNING synthetic_id
                    """,
                    synthetic_id,
                )
            except asyncpg.UniqueViolationError as exc:
                # Only the address index means "someone else has this address".
                # Any other unique violation is a different bug and must not be
                # reported as an address conflict.
                if exc.constraint_name != "idx_foss_users_email":
                    raise
                raise EmailAlreadyRegistered() from exc

            if row is None:
                return False

            # Evict here rather than in the caller. A state change must drop
            # the gate's memo or the user stays held at RELINKING for up to the
            # cache TTL after they are entitled through, and mark_relinked has
            # no caller in this PR to put it in -- part 2's runner and PRD-H's
            # override are both future code that would have to remember. The
            # import is local because gate imports db at module scope.
            #
            # In-process only: a runner in its own container evicts its own
            # empty cache and the API container's memo still expires on the TTL.
            # That is a bounded few seconds, not a correctness gap.
            #
            # Evicted AFTER the transaction commits, below -- not here. The
            # tombstone is stamped with the wall clock, so an in-process
            # verified_state starting between the evict and the commit has a
            # later clock, passes the tombstone check, and memoizes the
            # PRE-COMMIT value for a full TTL. Sub-millisecond and unreachable
            # today (the CLI is a separate process), but ops_override_write ten
            # functions down already evicts after its transaction and the two
            # should not disagree.

        # Reaching here means the transaction above committed.
        from src import gate as _gate
        _gate.evict(synthetic_id)

        # No audit row here. foss_users_audit's action vocabulary is a CHECK
        # constraint; the ops override is the caller that wants an actor
        # recorded, and it writes its own ops_override row.
        return True


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


async def verified_owner(email: str) -> Optional[str]:
    """The synthetic_id that has already VERIFIED this address, or None.

    lower(), matching idx_foss_users_email, for the reason spelled out in
    submit_email: EmailStr normalises only the domain, so a case-sensitive probe
    misses exactly the duplicates that index exists to catch.

    Unlike the probes inside submit_email and mark_pending_relink this returns
    the conflicting sid rather than a boolean, because the ops override has to
    name it: an operator handed "that address is taken" with no way to find out
    by whom cannot resolve anything, and resolving it -- deciding which of two
    accounts keeps an address -- is the human decision the refusal exists to
    hand back to them.

    Best-effort under READ COMMITTED, like the others: idx_foss_users_email is
    the enforcement, and mark_relinked is where it fires.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        return await conn.fetchval(
            """
            SELECT synthetic_id FROM foss_users
            WHERE lower(real_email) = lower($1) AND verified = TRUE
            LIMIT 1
            """,
            email,
        )


async def synthetic_id_exists(synthetic_id: str) -> bool:
    """Whether any row carries this synthetic_id.

    Used only by the ops override, to recognise `<other-sid>@<synthetic_domain>`
    as an identity token rather than a mailbox. verified_owner cannot see it:
    a synthetic address is never stored as anyone's real_email, so the probe has
    to be against synthetic_id instead.

    Case-insensitive, and that is load-bearing rather than tidy. The caller
    derives its argument from `email.lower().partition("@")`, because an email
    local part is compared case-insensitively -- so an exact match here would
    never fire for any synthetic_id containing an uppercase character. That is
    precisely the input the guard exists to catch: an operator pasting a sid
    verbatim out of `docker logs`, psql, or the ForwardAuth header. The probe
    would silently find nothing, the refusal would be skipped, and
    `<other-sid>@<domain>` would be written as this user's real_email with
    verified_owner unable to see it either.

    Recognising one address too many is safe -- the result is a refusal, and
    the operator is told which account they collided with. Recognising one too
    few is the account-takeover path.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        return (
            await conn.fetchval(
                "SELECT 1 FROM foss_users WHERE lower(synthetic_id) = lower($1) LIMIT 1",
                synthetic_id,
            )
            is not None
        )


async def ops_override_write(
    synthetic_id: str,
    email: str,
    *,
    audit_note: str,
) -> None:
    """Set a user's address on an operator's authority, and audit it.

    The row write and the audit write share one transaction, for the same reason
    submit_email's do: `foss_users_audit` is the record of *why* the platform
    holds this address, and a failure between the two would leave the address
    with no record of who set it or on what grounds. Here the reason is an
    operator's assertion rather than a user's consent, which makes the audit row
    more load-bearing, not less -- it is the only thing that says this address
    did not come from the user at all.

    `verified` is deliberately NOT touched:

    - The completing path (`manual`) sets it through `mark_relinked`, which is
      the only place that may, and which the caller invokes straight after.
    - The enqueueing path (`runner`) must not set it -- the overlay reads
      `WHERE verified` and the app accounts have not moved yet. The INSERT
      branch spells FALSE out for that reason; it is not the column default
      doing the work. Neither path sets it: mark_relinked is still the only
      thing that may, and the completing caller invokes it straight after.
    - Neither path CLEARS it. An unconditional downgrade here is the mistake
      submit_email's `WHERE foss_users.verified = FALSE` was added to prevent:
      it makes every app see a different principal and orphans the user's work.
      An already-relink-complete user is refused upstream in `runner` mode
      instead, and in `manual` mode the operator has asserted the app accounts
      are already on the new address.

    The verification token is cleared unconditionally. It was issued for the
    address the row held a moment ago; leaving it live would let a click on an
    old link move the user to pending_relink against an address the operator has
    just replaced.

    Both modes write `relink_state = 'pending_relink'`, which IS the queue --
    part 2's runner selects that state. There is deliberately no `enqueue`
    parameter: it used to select the state, then stopped affecting anything
    when both modes converged, and a keyword-only argument the body ignores is
    a trap for whoever writes part 2. The caller branches on `mode`, and
    `_audit_note` is what distinguishes the paths.

    **Constraint on part 2's runner:** it must select `pending_relink` AND
    `verified = FALSE`. A verified row in that state means the address is
    already live, and relinking app accounts onto it would move them to an
    address they were never keyed to.

    Consent columns are left NULL, which is truthful: no consent was recorded,
    because none was given. The operator's identity, the reason, and (for the
    completing path) the fact that the relink was asserted rather than verified
    go in `user_agent` as one structured string. They are deliberately NOT put
    in consent_text_version / consent_text_content -- those two columns are the
    consent artifact, and writing a non-consent event into them would
    permanently record an operator's justification as something the user agreed
    to. That is the same distinction submit_email draws when it writes
    'submit_email_collision' instead of 'submit_email'.
    """
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            try:
                await conn.execute(
                    """
                    INSERT INTO foss_users (
                        synthetic_id, real_email,
                        verification_token, verification_expires,
                        verified, relink_state, updated_at
                    ) VALUES (
                        -- pending_relink in both modes, same reason as the
                        -- conflict branch below: mark_relinked now refuses
                        -- ('none', FALSE), so the completing path must create the
                        -- row in the state it completes from. `verified` stays
                        -- FALSE either way -- only mark_relinked may set it.
                        $1, $2, NULL, NULL, FALSE, 'pending_relink',
                        now()
                    )
                    ON CONFLICT (synthetic_id) DO UPDATE
                    SET real_email = EXCLUDED.real_email,
                        verification_token = NULL,
                        verification_expires = NULL,
                        -- Always pending_relink, in BOTH modes. It used to be
                        -- left alone when completing, which worked only while
                        -- mark_relinked accepted any state. It now refuses
                        -- ('none', verified=FALSE) -- the user who submitted an
                        -- address and never opened the mail -- so the completing
                        -- path has to move the row into the state it is completing
                        -- FROM. That is also more honest: under `manual` the
                        -- operator has asserted the relink happened, so the row
                        -- genuinely is pending completion for the moment between
                        -- this write and mark_relinked.
                        relink_state = 'pending_relink',
                        updated_at = now()
                    """,
                    synthetic_id, email,
                )
            except asyncpg.UniqueViolationError as exc:
                # Setting real_email on an ALREADY-VERIFIED row makes the
                # partial index idx_foss_users_email apply to this statement.
                # verified_owner() probes for that first, but it is an unlocked
                # read under READ COMMITTED -- another account can verify the
                # same address between the probe and this write. Without this
                # the operator got a raw asyncpg traceback and exit 1, while the
                # command's documented contract is that 2 means refused. Same
                # shape mark_relinked already uses.
                if exc.constraint_name != "idx_foss_users_email":
                    raise
                raise EmailAlreadyRegistered(email) from exc

            try:
                await _insert_audit(
                    conn,
                    synthetic_id=synthetic_id,
                    action="ops_override",
                    email=email,
                    consent_text_version=None,
                    consent_text_content=None,
                    ip_address=None,
                    user_agent=audit_note,
                )
            except asyncpg.CheckViolationError as exc:
                # 'ops_override' is only an accepted action once the audit CHECK
                # has been widened -- a SEPARATE runbook step from the
                # relink_state block, so an upgrader can apply one and not the
                # other. Uncaught, this escaped run_override as a raw Postgres
                # traceback and exit 1, while the command's documented contract
                # is that 2 means refused. Nothing is lost either way (the audit
                # and row writes share this transaction, so the rollback is
                # clean), but an operator mid-incident has no way to tell that
                # the schema is the problem.
                if exc.constraint_name != "foss_users_audit_action_check":
                    raise
                raise AuditVocabularyMissing() from exc

    # Same reason mark_relinked evicts: the memo holds the address as well as
    # the state, so an override that did not evict would leave the gate handing
    # out the old answer for up to the TTL.
    #
    # In-process only. The override runs in its own `docker compose exec`
    # process, so it evicts a cache that is empty and the serving container's
    # memo still expires on its own TTL -- a bounded few seconds, the same
    # caveat mark_relinked carries for part 2's runner. The eviction is real
    # under pytest (one process) and that is what the test proves.
    from src import gate as _gate
    _gate.evict(synthetic_id)
