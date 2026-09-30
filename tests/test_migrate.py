"""`python -m src.migrate` against the suite's database.

The suite's schema is itself built by the migrate command (see the CI workflow),
so these tests cover what the command guarantees beyond "it ran once": that a
re-run changes nothing, that concurrent runs serialize, that the grants the
service depends on are in place, and that it refuses the wrong target.
"""
import asyncio

import asyncpg

from src import migrate
from tests.conftest import TEST_ADMIN_DSN

SNAPSHOT_QUERIES = (
    """SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid)
         FROM pg_constraint WHERE conrelid::regclass::text LIKE 'foss_users%'
        ORDER BY 1, 2""",
    """SELECT indexname, indexdef FROM pg_indexes
        WHERE tablename LIKE 'foss_users%' ORDER BY 1""",
    """SELECT table_name, column_name, data_type, is_nullable, column_default
         FROM information_schema.columns WHERE table_name LIKE 'foss_users%'
        ORDER BY 1, 2""",
    """SELECT grantee, table_name, privilege_type FROM information_schema.role_table_grants
        WHERE grantee IN ('launchpad_api_user', 'mpass_auth_user') ORDER BY 1, 2, 3""",
    """SELECT grantee, table_name, column_name, privilege_type
         FROM information_schema.column_privileges
        WHERE grantee IN ('launchpad_api_user', 'mpass_auth_user') ORDER BY 1, 2, 3, 4""",
)


async def schema_snapshot(conn: asyncpg.Connection) -> list[list[tuple]]:
    return [
        [tuple(row) for row in await conn.fetch(query)]
        for query in SNAPSHOT_QUERIES
    ]


async def test_reapplying_the_schema_changes_nothing(admin_conn):
    schema = migrate.SCHEMA_PATH.read_text()
    await migrate.apply_schema(TEST_ADMIN_DSN, schema)
    before = await schema_snapshot(admin_conn)

    await migrate.apply_schema(TEST_ADMIN_DSN, schema)

    assert await schema_snapshot(admin_conn) == before


async def test_concurrent_runs_serialize_instead_of_deadlocking():
    schema = migrate.SCHEMA_PATH.read_text()

    await asyncio.gather(*(migrate.apply_schema(TEST_ADMIN_DSN, schema) for _ in range(4)))


async def test_both_roles_are_present(admin_conn):
    assert await migrate.missing_roles(admin_conn) == []


async def test_refuses_a_database_other_than_launchpad(admin_conn, monkeypatch):
    monkeypatch.setenv("DB_NAME", "not_launchpad")

    reason = await migrate.refusal_reason(admin_conn)

    assert reason is not None and "not_launchpad" in reason


async def test_mpass_role_cannot_read_verification_tokens(admin_conn):
    readable = await admin_conn.fetch(
        """
        SELECT column_name FROM information_schema.column_privileges
         WHERE grantee = 'mpass_auth_user' AND table_name = 'foss_users'
           AND privilege_type = 'SELECT'
        """
    )

    assert {row["column_name"] for row in readable} == {"synthetic_id", "real_email", "verified"}


async def test_api_role_cannot_erase_the_audit_trail(admin_conn):
    privileges = await admin_conn.fetch(
        """
        SELECT privilege_type FROM information_schema.role_table_grants
         WHERE grantee = 'launchpad_api_user' AND table_name = 'foss_users_audit'
        """
    )

    assert {row["privilege_type"] for row in privileges} == {"SELECT", "INSERT"}


def test_refuses_to_run_without_a_dsn(monkeypatch, capsys):
    monkeypatch.delenv(migrate.DSN_ENV, raising=False)

    assert migrate.main() == 2
    assert migrate.DSN_ENV in capsys.readouterr().err


def test_reports_an_unreachable_host_without_a_traceback(monkeypatch, capsys):
    monkeypatch.setenv(migrate.DSN_ENV, "postgresql://u:secret@no-such-host.invalid:5432/launchpad")

    assert migrate.main() == 1
    err = capsys.readouterr().err
    assert "cannot connect" in err and "secret" not in err
