"""PRD §6.1 — Migration (§1.4).

Proves that step 2 of the runbook migration does what its comment claims: a
pre-existing plaintext token is invalidated, so any link already sitting in an
inbox stops working, and the affected user recovers by clicking "Resend".

The SQL below is a verbatim copy of the §1.4 block. It is duplicated rather
than parsed out of dev/docs/launchpad-runbook.md (lane 1's file): extracting
SQL from markdown is brittle, and the PRD specifies the statements exactly.
Keep the two in sync.
"""
import secrets

import asyncpg
import pytest

from src import db
from tests.conftest import mailpit_messages, mailpit_token, new_email, new_sid

# Kept in step with dev/docs/launchpad-runbook.md's migration block. It is a
# verbatim copy rather than a parse of the doc, so drift is possible -- and did
# happen once: this list kept the case-sensitive index and no pre-flight for a
# while after the runbook gained both, so the test validated a migration nobody
# would run. If you change one, change the other.
PREFLIGHT_SQL = """
DO $$
DECLARE dupes TEXT;
BEGIN
    SELECT string_agg(DISTINCT lower(real_email), ', ')
      INTO dupes
      FROM foss_users
     WHERE verified
     GROUP BY lower(real_email)
    HAVING count(*) > 1;

    IF dupes IS NOT NULL THEN
        RAISE EXCEPTION
            'Cannot apply the case-insensitive index: these addresses are '
            'verified on more than one account, differing only in case: %. '
            'Decide which account keeps each address, UPDATE foss_users SET '
            'verified = FALSE for the others, then re-run this migration.',
            dupes;
    END IF;
END
$$
"""

MIGRATION_SQL = [
    # 1. Partial, case-insensitive index -- pre-flight first, so a database
    #    holding mixed-case verified duplicates is refused *before* the DROP
    #    rather than left with no unique index at all.
    PREFLIGHT_SQL,
    "DROP INDEX IF EXISTS idx_foss_users_email",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_foss_users_email "
    "ON foss_users(lower(real_email)) WHERE verified",
    # 2. Invalidate pre-existing plaintext tokens.
    "UPDATE foss_users SET verification_token = NULL, verification_expires = NULL "
    "WHERE verified = FALSE",
    # 3. Narrow the read-only grant
    "REVOKE SELECT ON foss_users FROM mpass_auth_user",
    "GRANT SELECT (synthetic_id, real_email, verified) ON foss_users TO mpass_auth_user",
    # 4. Widen the audit action vocabulary
    "ALTER TABLE foss_users_audit DROP CONSTRAINT IF EXISTS foss_users_audit_action_check",
    "ALTER TABLE foss_users_audit ADD CONSTRAINT foss_users_audit_action_check "
    "CHECK (action IN ('submit_email', 'verify_email', 'resend_verification', "
    "'dismiss_modal', 'submit_email_collision', 'rate_limited', 'ops_override'))",
    # 5. The audit table is append-only; revoke DELETE from the API role. A
    #    REVOKE of a privilege that was never granted is a no-op, which is what
    #    makes the block safe to run against a database already in shape.
    "REVOKE DELETE ON foss_users_audit FROM launchpad_api_user",
]


async def _snapshot(conn) -> dict:
    return {
        "index": await conn.fetchval(
            "SELECT pg_get_indexdef(oid) FROM pg_class WHERE relname = 'idx_foss_users_email'"
        ),
        "check": await conn.fetchval(
            "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
            "WHERE conname = 'foss_users_audit_action_check'"
        ),
        "table_select": await conn.fetchval(
            "SELECT has_table_privilege('mpass_auth_user', 'foss_users', 'SELECT')"
        ),
        # Captured separately: has_table_privilege() reports FALSE when only
        # column-level SELECT is granted, which is exactly the post-migration
        # shape this fixture has to be able to restore.
        "column_select": await conn.fetchval(
            "SELECT has_column_privilege("
            "'mpass_auth_user', 'foss_users', 'real_email', 'SELECT')"
        ),
    }


@pytest.fixture
async def migrated_schema(admin_conn, cleanup_test_users):
    """Apply the §1.4 migration, then put the schema back exactly as found.

    Without the restore the shared launchpad database would flip mid-suite and
    every later test would see a different schema than the earlier ones.
    """
    original = await _snapshot(admin_conn)
    try:
        yield admin_conn
    finally:
        await admin_conn.execute(
            "DELETE FROM foss_users WHERE synthetic_id LIKE 'test_%'"
        )
        await admin_conn.execute(
            "DELETE FROM foss_users_audit WHERE synthetic_id LIKE 'test_%'"
        )
        await admin_conn.execute("DROP INDEX IF EXISTS idx_foss_users_email")
        if original["index"]:
            await admin_conn.execute(original["index"])
        await admin_conn.execute(
            "ALTER TABLE foss_users_audit DROP CONSTRAINT IF EXISTS "
            "foss_users_audit_action_check"
        )
        if original["check"]:
            await admin_conn.execute(
                "ALTER TABLE foss_users_audit ADD CONSTRAINT "
                f"foss_users_audit_action_check {original['check']}"
            )
        # has_table_privilege() is FALSE for a column-level grant, so keying the
        # restore on it alone meant that on any database already in the target
        # shape -- i.e. every database this PR creates -- the teardown revoked
        # (which also drops column grants) and then restored nothing. That
        # silently disables mpass-auth-proxy's only query, and its overlay fails
        # closed, so the symptom is nobody being able to log in to any app.
        await admin_conn.execute("REVOKE SELECT ON foss_users FROM mpass_auth_user")
        if original["table_select"]:
            await admin_conn.execute("GRANT SELECT ON foss_users TO mpass_auth_user")
        elif original["column_select"]:
            await admin_conn.execute(
                "GRANT SELECT (synthetic_id, real_email, verified) "
                "ON foss_users TO mpass_auth_user"
            )


async def _apply_migration(conn) -> None:
    for statement in MIGRATION_SQL:
        await conn.execute(statement)


async def test_migration_is_idempotent(migrated_schema):
    """DoD: runs twice consecutively with no error."""
    await _apply_migration(migrated_schema)
    await _apply_migration(migrated_schema)


async def test_pre_migration_link_stops_working_and_resend_restores_it(
    raw_client, migrated_schema, clean_mailbox
):
    sid = new_sid()
    email = new_email("migrate")

    # A row as it existed before §1.2: a *plaintext* token in the column.
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO foss_users (
                synthetic_id, real_email, verification_token,
                verification_expires, verified, updated_at
            ) VALUES ($1, $2, 'legacy-plaintext-token',
                      now() + interval '24 hours', FALSE, now())
            """,
            sid, email,
        )

    await _apply_migration(migrated_schema)

    # Step 2 did what its comment claims.
    user = await db.fetch_user(sid)
    assert user["verification_token"] is None
    assert user["verification_expires"] is None

    # The link already in the user's inbox is dead.
    dead = await raw_client.get(
        "/api/verify?token=legacy-plaintext-token", follow_redirects=False
    )
    assert dead.status_code == 302
    assert "verify_error=expired_or_invalid" in dead.headers["location"]
    assert (await db.fetch_user(sid))["verified"] is False

    # Resend gives them a working one.
    resend = await raw_client.post(
        "/api/email/resend", headers={"X-Auth-Request-Preferred-Username": sid}
    )
    assert resend.status_code == 200

    messages = await mailpit_messages()
    assert messages, "resend delivered no mail"
    fresh = await mailpit_token(messages[0]["ID"])

    ok = await raw_client.get(f"/api/verify?token={fresh}", follow_redirects=False)
    # The click lands them in pending_relink, not verified -- clicking a link
    # never sets verified any more.
    assert "relinking=1" in ok.headers["location"]
    user = await db.fetch_user(sid)
    assert user["verified"] is False
    assert user["relink_state"] == "pending_relink"


async def test_migration_admits_the_new_audit_actions(migrated_schema):
    """Step 4: the widened CHECK accepts the two new action values (§1.3)."""
    await _apply_migration(migrated_schema)

    sid = new_sid()
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        for action in (
            "submit_email_collision", "rate_limited", "dismiss_modal",
            # The ops override's action. It is in this list because the CHECK is
            # the only thing standing between the override and a 500 on a
            # database that was migrated before FOSS-13 -- the vocabulary lives
            # in four places (postgres/init-databases.sh, the runbook's step 4,
            # MIGRATION_SQL above, and here) and this is the assertion that
            # notices when one of them is missed.
            "ops_override",
        ):
            await conn.execute(
                "INSERT INTO foss_users_audit (synthetic_id, action) VALUES ($1, $2)",
                sid, action,
            )


async def test_migration_makes_the_email_index_partial(migrated_schema):
    """Step 1: unverified rows no longer claim an address exclusively."""
    await _apply_migration(migrated_schema)

    email = new_email("partial")
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        for _ in range(2):
            await conn.execute(
                "INSERT INTO foss_users (synthetic_id, real_email, verified, updated_at) "
                "VALUES ($1, $2, FALSE, now())",
                new_sid(), email,
            )
        count = await conn.fetchval(
            "SELECT count(*) FROM foss_users WHERE real_email = $1", email
        )
    assert count == 2


async def test_migration_hides_tokens_from_the_read_only_role(migrated_schema):
    """Step 3, both directions (§7 grant verification)."""
    import asyncpg

    from src.config import settings

    dsn = (
        f"postgresql://mpass_auth_user:testpw2@{settings.db_host}:"
        f"{settings.db_port}/{settings.db_name}"
    )
    await _apply_migration(migrated_schema)

    conn = await asyncpg.connect(dsn)
    try:
        # mpass-auth-proxy's only query must still work.
        await conn.fetch(
            "SELECT real_email FROM foss_users WHERE synthetic_id = $1 AND verified = TRUE",
            "test_nobody",
        )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.fetch("SELECT verification_token FROM foss_users LIMIT 1")
    finally:
        await conn.close()


async def test_migration_refuses_mixed_case_duplicates_without_dropping(admin_conn):
    """The pre-flight must refuse *before* the DROP.

    The old index was case-sensitive, so it permitted two verified rows
    differing only in case. Creating the lower() index on such a database fails
    -- and without the pre-flight it failed after DROP INDEX, leaving the table
    with no uniqueness constraint and no squatting protection, mid-migration.
    """
    a, b = f"test_{secrets.token_hex(4)}", f"test_{secrets.token_hex(4)}"
    addr = f"Mixed.{secrets.token_hex(3)}@Example.com"
    try:
        # Put the table back into the pre-migration shape for this test.
        await admin_conn.execute("DROP INDEX IF EXISTS idx_foss_users_email")
        await admin_conn.execute(
            "CREATE UNIQUE INDEX idx_foss_users_email "
            "ON foss_users(real_email) WHERE verified"
        )
        for sid, email in ((a, addr), (b, addr.lower())):
            await admin_conn.execute(
                "INSERT INTO foss_users (synthetic_id, real_email, verified, updated_at)"
                " VALUES ($1, $2, TRUE, now())",
                sid, email,
            )

        with pytest.raises(asyncpg.RaiseError) as exc:
            await admin_conn.execute(PREFLIGHT_SQL)
        assert "differing only in case" in str(exc.value)
        assert addr.lower() in str(exc.value)

        # The old index must still be there -- refusing before touching anything
        # is the whole point.
        indexdef = await admin_conn.fetchval(
            "SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_foss_users_email'"
        )
        assert indexdef is not None, "pre-flight must not drop the index it refuses on"
        assert "lower(real_email)" not in indexdef

        # Once the operator resolves the conflict, the migration applies.
        await admin_conn.execute(
            "UPDATE foss_users SET verified = FALSE WHERE synthetic_id = $1", b
        )
        for statement in MIGRATION_SQL:
            await admin_conn.execute(statement)
        indexdef = await admin_conn.fetchval(
            "SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_foss_users_email'"
        )
        assert "lower(real_email)" in indexdef
    finally:
        await admin_conn.execute(
            "DELETE FROM foss_users WHERE synthetic_id LIKE 'test_%'"
        )
        await admin_conn.execute("DROP INDEX IF EXISTS idx_foss_users_email")
        await admin_conn.execute(
            "CREATE UNIQUE INDEX idx_foss_users_email "
            "ON foss_users(lower(real_email)) WHERE verified"
        )
