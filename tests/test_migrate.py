"""`python -m src.migrate` against the suite's database.

The suite's schema is itself built by the migrate command (see the CI workflow),
so these tests cover what the command guarantees beyond "it ran once": that a
second run is a no-op, that the grants the service depends on are in place,
and that it refuses to start without a DSN.
"""
from src import migrate
from tests.conftest import TEST_ADMIN_DSN


async def test_reapplying_the_schema_is_a_no_op():
    schema = migrate.SCHEMA_PATH.read_text()

    await migrate.apply_schema(TEST_ADMIN_DSN, schema)
    await migrate.apply_schema(TEST_ADMIN_DSN, schema)


async def test_both_roles_are_present(admin_conn):
    assert await migrate.missing_roles(admin_conn) == []


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
