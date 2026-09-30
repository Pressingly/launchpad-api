"""The `relink_state` migration from sql/schema.sql.

There is still no migration framework, so the column ships as an ALTER block
inside the schema that `python -m src.migrate` applies.
The SQL below mirrors that block, in the same order. It is duplicated rather
than parsed out of the file -- extracting statements from a .sql script full of
psql meta-commands and dollar-quoted blocks is brittle -- and it has drifted
once before (the §1.4 mirror in test_prc_migration.py kept a case-sensitive
index for a while after the source gained a pre-flight, so it validated a
migration nobody would run).
**If you change one, change the other.**

This previously mirrored a hand-run block in dev/docs/launchpad-runbook.md. That
block was replaced by the provisioning command; the runbook now points at the
script rather than carrying its own copy of the SQL.

One deliberate difference from the source: `src.migrate` applies the whole of
sql/schema.sql in one transaction, so a validation failure cannot leave the
table with no constraint at all.
These tests drive the statements individually through asyncpg, where each gets
its own implicit transaction, so that pairing is not reproduced here. The
pre-flight below is what makes the failure diagnosable in both.

What these tests are for: `fetch_user` selects named columns and now names
`relink_state`, so the service raises against a database without it. The stated
deploy order is migration first, then code -- so the migration has to be the
thing that is proven, not assumed.
"""
import pytest

from src import db, gate
from tests.conftest import new_email, new_sid

PREFLIGHT_SQL = """
DO $$
DECLARE bad TEXT;
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
                WHERE table_name = 'foss_users' AND column_name = 'relink_state') THEN
        SELECT string_agg(DISTINCT coalesce(relink_state, '<null>'), ', ')
          INTO bad
          FROM foss_users
         WHERE relink_state IS NULL
            OR relink_state NOT IN ('none', 'pending_relink', 'relinked');

        IF bad IS NOT NULL THEN
            RAISE EXCEPTION
                'Cannot apply the relink_state constraint: existing rows hold '
                'values outside the vocabulary: %. Decide what each row should '
                'be (none | pending_relink | relinked), UPDATE them, then '
                're-run this migration.', bad;
        END IF;
    END IF;
END
$$
"""

MIGRATION_SQL = [
    # 1. Pre-flight: refuse before touching anything.
    PREFLIGHT_SQL,
    # 2. The column. Existing rows land on 'none'.
    "ALTER TABLE foss_users "
    "ADD COLUMN IF NOT EXISTS relink_state TEXT NOT NULL DEFAULT 'none'",
    # 3. The vocabulary, named and dropped first so a re-run replaces it.
    "ALTER TABLE foss_users DROP CONSTRAINT IF EXISTS foss_users_relink_state_check",
    "ALTER TABLE foss_users ADD CONSTRAINT foss_users_relink_state_check "
    "CHECK (relink_state IN ('none', 'pending_relink', 'relinked'))",
    # 4. The column comment, so `\d+ foss_users` explains the legacy case.
    "COMMENT ON COLUMN foss_users.relink_state IS "
    "'How far the app-account relink has got: none | pending_relink | relinked. "
    "verified = TRUE with relink_state = ''none'' is the legacy combination "
    "(verified before this column existed) and is treated as complete.'",
]


async def _apply_migration(conn) -> None:
    for statement in MIGRATION_SQL:
        await conn.execute(statement)


@pytest.fixture
async def unmigrated_schema(admin_conn, cleanup_test_users):
    """Put the table back in its pre-migration shape, then restore it exactly.

    Without the restore the shared launchpad database would be left without the
    column and every later test in the run would fail against a schema the
    service does not support.
    """
    await admin_conn.execute(
        "ALTER TABLE foss_users DROP CONSTRAINT IF EXISTS foss_users_relink_state_check"
    )
    await admin_conn.execute("ALTER TABLE foss_users DROP COLUMN IF EXISTS relink_state")
    try:
        yield admin_conn
    finally:
        await admin_conn.execute(
            "DELETE FROM foss_users WHERE synthetic_id LIKE 'test_%'"
        )
        await admin_conn.execute(
            "DELETE FROM foss_users_audit WHERE synthetic_id LIKE 'test_%'"
        )
        await admin_conn.execute(
            "ALTER TABLE foss_users DROP CONSTRAINT IF EXISTS "
            "foss_users_relink_state_check"
        )
        await admin_conn.execute(
            "ALTER TABLE foss_users DROP COLUMN IF EXISTS relink_state"
        )
        await admin_conn.execute(
            "ALTER TABLE foss_users ADD COLUMN relink_state TEXT NOT NULL "
            "DEFAULT 'none' CONSTRAINT foss_users_relink_state_check "
            "CHECK (relink_state IN ('none', 'pending_relink', 'relinked'))"
        )


async def _seed_raw(conn, sid: str, email: str, verified: bool) -> None:
    """Insert directly, naming only pre-migration columns -- the row has to be
    insertable on a database that does not have relink_state yet."""
    await conn.execute(
        "INSERT INTO foss_users (synthetic_id, real_email, verified, verified_at, "
        "updated_at) VALUES ($1, $2, $3, CASE WHEN $3 THEN now() END, now())",
        sid, email, verified,
    )


async def test_migration_adds_the_column(unmigrated_schema):
    conn = unmigrated_schema
    assert await conn.fetchval(
        "SELECT count(*) FROM information_schema.columns "
        "WHERE table_name = 'foss_users' AND column_name = 'relink_state'"
    ) == 0

    await _apply_migration(conn)

    row = await conn.fetchrow(
        "SELECT is_nullable, column_default, data_type "
        "FROM information_schema.columns "
        "WHERE table_name = 'foss_users' AND column_name = 'relink_state'"
    )
    assert row is not None
    assert row["is_nullable"] == "NO"
    assert "'none'" in row["column_default"]
    assert row["data_type"] == "text"


async def test_migration_is_idempotent(unmigrated_schema):
    """Runs twice consecutively with no error, and once more against a database
    that was already in the target shape."""
    await _apply_migration(unmigrated_schema)
    await _apply_migration(unmigrated_schema)

    assert await unmigrated_schema.fetchval(
        "SELECT count(*) FROM pg_constraint "
        "WHERE conrelid = 'foss_users'::regclass "
        "AND conname = 'foss_users_relink_state_check'"
    ) == 1


async def test_existing_verified_rows_land_in_the_legacy_combination(
    unmigrated_schema,
):
    """Every pre-existing row gets 'none'. For an already-verified row that is
    the legacy combination, which must be treated as relink-complete -- holding
    it would lock out accounts that predate the column for no reason."""
    conn = unmigrated_schema
    verified_sid, unverified_sid = new_sid(), new_sid()
    await _seed_raw(conn, verified_sid, new_email("legacy"), True)
    await _seed_raw(conn, unverified_sid, new_email("legacy"), False)

    await _apply_migration(conn)

    rows = {
        r["synthetic_id"]: (r["verified"], r["relink_state"])
        for r in await conn.fetch(
            "SELECT synthetic_id, verified, relink_state FROM foss_users "
            "WHERE synthetic_id = ANY($1::text[])",
            [verified_sid, unverified_sid],
        )
    }
    assert rows[verified_sid] == (True, "none")
    assert rows[unverified_sid] == (False, "none")

    assert gate.is_relink_complete(verified=True, relink_state="none") is True
    assert gate.is_relink_complete(verified=False, relink_state="none") is False


async def test_migration_enforces_the_vocabulary(unmigrated_schema):
    conn = unmigrated_schema
    sid = new_sid()
    await _seed_raw(conn, sid, new_email("vocab"), False)
    await _apply_migration(conn)

    with pytest.raises(Exception) as exc:
        await conn.execute(
            "UPDATE foss_users SET relink_state = 'nonsense' WHERE synthetic_id = $1",
            sid,
        )
    assert "foss_users_relink_state_check" in str(exc.value)


async def test_preflight_refuses_before_the_constraint_is_added(unmigrated_schema):
    """The pre-flight must refuse rather than half-apply.

    Only reachable where somebody added the column by hand, or where a previous
    run was interrupted between the column and the CHECK. It matters because
    ADD CONSTRAINT validates existing rows: without the pre-flight the block
    fails on the constraint, after the column is already there, and the error
    points at the wrong statement.
    """
    conn = unmigrated_schema
    sid = new_sid()
    await _seed_raw(conn, sid, new_email("preflight"), False)
    # A hand-added column with no constraint, holding a value outside the
    # vocabulary -- the partially-migrated database this guard is for.
    await conn.execute(
        "ALTER TABLE foss_users ADD COLUMN relink_state TEXT NOT NULL DEFAULT 'none'"
    )
    await conn.execute(
        "UPDATE foss_users SET relink_state = 'garbage' WHERE synthetic_id = $1", sid
    )

    with pytest.raises(Exception) as exc:
        await _apply_migration(conn)
    assert "outside the vocabulary" in str(exc.value)
    assert "garbage" in str(exc.value)

    # ... and it stopped at the pre-flight: no constraint was added.
    assert await conn.fetchval(
        "SELECT count(*) FROM pg_constraint "
        "WHERE conrelid = 'foss_users'::regclass "
        "AND conname = 'foss_users_relink_state_check'"
    ) == 0


async def test_the_read_only_role_still_cannot_read_relink_state(unmigrated_schema):
    """mpass_auth_user's grant is column-scoped to (synthetic_id, real_email,
    verified) and the migration deliberately does not widen it. The overlay's
    contract is "verified means usable" and nothing else.

    Asserted with has_column_privilege over the superuser connection rather than
    by logging in as the role, so the test does not have to know that role's
    password -- which lives in the environment and is not part of this contract.
    """
    conn = unmigrated_schema

    await _apply_migration(conn)

    for column, expected in [
        ("real_email", True),
        ("verified", True),
        ("relink_state", False),
    ]:
        granted = await conn.fetchval(
            "SELECT has_column_privilege('mpass_auth_user', 'foss_users', $1, 'SELECT')",
            column,
        )
        assert granted is expected, f"mpass_auth_user SELECT on {column}"


async def test_fetch_user_needs_the_column(unmigrated_schema):
    """The DoD's deploy order, asserted rather than described: the code does NOT
    tolerate a missing column. Apply the migration, then deploy."""
    import asyncpg

    sid = new_sid()
    await _seed_raw(unmigrated_schema, sid, new_email("order"), False)

    with pytest.raises(asyncpg.UndefinedColumnError):
        await db.fetch_user(sid)

    await _apply_migration(unmigrated_schema)
    assert (await db.fetch_user(sid))["relink_state"] == "none"
