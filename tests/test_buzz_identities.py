"""buzz_identities: the constraints and grants mpass-auth-proxy's key binding
relies on.

Role checks run inside a rolled-back transaction under `SET LOCAL ROLE`, so they
exercise the privileges each role really has and leave no rows behind."""
import secrets

import asyncpg
import pytest

from src import migrate
from tests.conftest import TEST_ADMIN_DSN

MPASS_BINDING_SQL = (
    "INSERT INTO buzz_identities (sub, pubkey_hex, email) VALUES ($1, $2, $3) "
    "ON CONFLICT (sub) DO NOTHING"
)


def new_pubkey() -> str:
    return secrets.token_hex(32)


def new_sub() -> str:
    return f"test_buzz_{secrets.token_hex(4)}"


@pytest.fixture
async def rolled_back(admin_conn):
    transaction = admin_conn.transaction()
    await transaction.start()
    try:
        yield admin_conn
    finally:
        await transaction.rollback()


async def as_role(conn: asyncpg.Connection, role: str) -> None:
    await conn.execute(f"SET LOCAL ROLE {role}")


async def table_privileges(conn: asyncpg.Connection, role: str) -> set[str]:
    rows = await conn.fetch(
        """
        SELECT privilege_type FROM information_schema.role_table_grants
         WHERE grantee = $1 AND table_name = 'buzz_identities'
        """,
        role,
    )
    return {row["privilege_type"] for row in rows}


async def columns_with(conn: asyncpg.Connection, role: str, privilege: str) -> set[str]:
    rows = await conn.fetch(
        """
        SELECT column_name FROM information_schema.column_privileges
         WHERE grantee = $1 AND table_name = 'buzz_identities' AND privilege_type = $2
        """,
        role,
        privilege,
    )
    return {row["column_name"] for row in rows}


class TestGrants:
    async def test_mpass_role_reads_but_holds_no_table_wide_write(self, admin_conn):
        assert await table_privileges(admin_conn, "mpass_auth_user") == {"SELECT"}

    async def test_mpass_role_may_insert_only_the_binding_columns(self, admin_conn):
        assert await columns_with(admin_conn, "mpass_auth_user", "INSERT") == {"sub", "pubkey_hex", "email"}

    async def test_mpass_role_may_update_only_revoked_at(self, admin_conn):
        assert await columns_with(admin_conn, "mpass_auth_user", "UPDATE") == {"revoked_at"}

    async def test_api_role_only_reads(self, admin_conn):
        assert await table_privileges(admin_conn, "launchpad_api_user") == {"SELECT"}
        assert await columns_with(admin_conn, "launchpad_api_user", "UPDATE") == set()

    async def test_foss_users_grant_for_mpass_role_is_unchanged(self, admin_conn):
        rows = await admin_conn.fetch(
            """
            SELECT column_name FROM information_schema.column_privileges
             WHERE grantee = 'mpass_auth_user' AND table_name = 'foss_users'
            """
        )
        assert {row["column_name"] for row in rows} == {"synthetic_id", "real_email", "verified"}


class TestMpassRoleAtRuntime:
    async def test_binds_a_key_and_reads_it_back(self, rolled_back):
        sub, pubkey = new_sub(), new_pubkey()
        await as_role(rolled_back, "mpass_auth_user")

        await rolled_back.execute(MPASS_BINDING_SQL, sub, pubkey, "jane@example.com")
        await rolled_back.execute(MPASS_BINDING_SQL, sub, new_pubkey(), "jane@example.com")

        row = await rolled_back.fetchrow(
            "SELECT pubkey_hex, revoked_at FROM buzz_identities WHERE sub = $1", sub
        )
        assert row["pubkey_hex"] == pubkey
        assert row["revoked_at"] is None

    async def test_can_revoke(self, rolled_back):
        sub = new_sub()
        await as_role(rolled_back, "mpass_auth_user")
        await rolled_back.execute(MPASS_BINDING_SQL, sub, new_pubkey(), None)

        await rolled_back.execute("UPDATE buzz_identities SET revoked_at = now() WHERE sub = $1", sub)

        assert await rolled_back.fetchval(
            "SELECT revoked_at IS NOT NULL FROM buzz_identities WHERE sub = $1", sub
        )

    @pytest.mark.parametrize("statement", [
        "UPDATE buzz_identities SET pubkey_hex = '" + "0" * 64 + "' WHERE sub = $1",
        "UPDATE buzz_identities SET email = 'other@example.com' WHERE sub = $1",
        "DELETE FROM buzz_identities WHERE sub = $1",
    ])
    async def test_cannot_rebind_or_erase(self, rolled_back, statement):
        sub = new_sub()
        await as_role(rolled_back, "mpass_auth_user")
        await rolled_back.execute(MPASS_BINDING_SQL, sub, new_pubkey(), None)

        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await rolled_back.execute(statement, sub)

    @pytest.mark.parametrize("column, value", [
        ("revoked_at", "now()"),
        ("created_at", "'2020-01-01'::timestamptz"),
    ])
    async def test_cannot_insert_pre_revoked_or_backdated_rows(self, rolled_back, column, value):
        await as_role(rolled_back, "mpass_auth_user")

        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await rolled_back.execute(
                f"INSERT INTO buzz_identities (sub, pubkey_hex, {column}) VALUES ($1, $2, {value})",
                new_sub(), new_pubkey(),
            )

    async def test_api_role_cannot_write(self, rolled_back):
        await as_role(rolled_back, "launchpad_api_user")

        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await rolled_back.execute(MPASS_BINDING_SQL, new_sub(), new_pubkey(), None)


class TestConstraints:
    @pytest.mark.parametrize("pubkey", [
        "AB" * 32,
        "ab" * 31 + "a",
        "ab" * 32 + "a",
        "zz" * 32,
        "ab" * 32 + "\n",
        "",
    ])
    async def test_rejects_anything_but_64_lowercase_hex(self, rolled_back, pubkey):
        with pytest.raises(asyncpg.CheckViolationError):
            await rolled_back.execute(MPASS_BINDING_SQL, new_sub(), pubkey, None)

    async def test_one_key_cannot_be_bound_to_two_people(self, rolled_back):
        pubkey = new_pubkey()
        await rolled_back.execute(MPASS_BINDING_SQL, new_sub(), pubkey, None)

        with pytest.raises(asyncpg.UniqueViolationError):
            await rolled_back.execute(MPASS_BINDING_SQL, new_sub(), pubkey, None)

    async def test_one_person_has_one_row(self, rolled_back):
        sub = new_sub()
        await rolled_back.execute(MPASS_BINDING_SQL, sub, new_pubkey(), None)

        with pytest.raises(asyncpg.UniqueViolationError):
            await rolled_back.execute(
                "INSERT INTO buzz_identities (sub, pubkey_hex) VALUES ($1, $2)", sub, new_pubkey()
            )

    async def test_defaults(self, rolled_back):
        sub = new_sub()
        await rolled_back.execute(MPASS_BINDING_SQL, sub, new_pubkey(), None)

        row = await rolled_back.fetchrow(
            "SELECT email, created_at, revoked_at FROM buzz_identities WHERE sub = $1", sub
        )
        assert row["email"] is None
        assert row["created_at"] is not None
        assert row["revoked_at"] is None


async def revoked_identity(conn: asyncpg.Connection) -> str:
    sub = new_sub()
    await conn.execute(MPASS_BINDING_SQL, sub, new_pubkey(), None)
    await conn.execute("UPDATE buzz_identities SET revoked_at = now() WHERE sub = $1", sub)
    return sub


class TestRevocationIsFinal:
    @pytest.mark.parametrize("role", ["mpass_auth_user", None])
    @pytest.mark.parametrize("new_value", ["NULL", "now() + interval '1 day'"])
    async def test_set_revoked_at_cannot_be_cleared_or_changed(self, rolled_back, role, new_value):
        if role:
            await as_role(rolled_back, role)
        sub = await revoked_identity(rolled_back)

        with pytest.raises(asyncpg.RaiseError, match="revocation of .* is final"):
            await rolled_back.execute(f"UPDATE buzz_identities SET revoked_at = {new_value} WHERE sub = $1", sub)

    async def test_revoking_twice_with_the_same_value_is_a_no_op(self, rolled_back):
        await as_role(rolled_back, "mpass_auth_user")
        sub = await revoked_identity(rolled_back)

        await rolled_back.execute("UPDATE buzz_identities SET revoked_at = revoked_at WHERE sub = $1", sub)

    async def test_other_columns_of_a_revoked_row_stay_editable_by_the_owner(self, rolled_back):
        sub = await revoked_identity(rolled_back)

        await rolled_back.execute("UPDATE buzz_identities SET email = 'ops@example.com' WHERE sub = $1", sub)

    async def test_reapplying_the_schema_keeps_exactly_one_trigger(self, admin_conn):
        schema = migrate.SCHEMA_PATH.read_text()
        await migrate.apply_schema(TEST_ADMIN_DSN, schema)
        await migrate.apply_schema(TEST_ADMIN_DSN, schema)

        triggers = await admin_conn.fetch(
            """
            SELECT tgname FROM pg_trigger
             WHERE tgrelid = 'buzz_identities'::regclass AND NOT tgisinternal
            """
        )
        assert [row["tgname"] for row in triggers] == ["buzz_identities_revocation_is_final"]
