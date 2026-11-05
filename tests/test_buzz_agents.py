"""buzz_agents: the constraints, trigger and grants mpass-auth-proxy's agent
enrollment relies on.

Role checks run inside a rolled-back transaction under `SET LOCAL ROLE`, so they
exercise the privileges each role really has and leave no rows behind."""
import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import asyncpg
import pytest

from src import migrate
from tests.conftest import TEST_ADMIN_DSN
from tests.test_buzz_identities import (
    MPASS_BINDING_SQL,
    as_role,
    new_pubkey,
    new_sub,
    rolled_back,  # noqa: F401  (fixture applies by import)
)

ENROLL_SQL = (
    "INSERT INTO buzz_agents (agent_pubkey, owner_sub, grant_hash, grant_expires_at) "
    "VALUES ($1, $2, $3, now() + interval '8 days')"
)
REPLACE_GRANT_SQL = (
    "UPDATE buzz_agents SET grant_hash = $2, grant_expires_at = now() + interval '8 days' "
    "WHERE agent_pubkey = $1"
)
REVOKE_SQL = (
    "UPDATE buzz_agents SET revoked_at = now(), grant_hash = NULL, grant_expires_at = NULL "
    "WHERE agent_pubkey = $1 AND revoked_at IS NULL"
)
TRIGGER_NAME = "buzz_agents_owner_and_revocation_are_final"


def new_grant_hash() -> str:
    return hashlib.sha256(secrets.token_bytes(32)).hexdigest()


async def new_owner(conn: asyncpg.Connection) -> str:
    sub = new_sub()
    await conn.execute(MPASS_BINDING_SQL, sub, new_pubkey(), None)
    return sub


async def enrolled_agent(conn: asyncpg.Connection, owner_sub: str | None = None) -> str:
    agent = new_pubkey()
    await conn.execute(ENROLL_SQL, agent, owner_sub or await new_owner(conn), new_grant_hash())
    return agent


async def revoked_agent(conn: asyncpg.Connection) -> str:
    agent = await enrolled_agent(conn)
    await conn.execute(REVOKE_SQL, agent)
    return agent


async def table_privileges(conn: asyncpg.Connection, role: str) -> set[str]:
    rows = await conn.fetch(
        """
        SELECT privilege_type FROM information_schema.role_table_grants
         WHERE grantee = $1 AND table_name = 'buzz_agents'
        """,
        role,
    )
    return {row["privilege_type"] for row in rows}


async def columns_with(conn: asyncpg.Connection, role: str, privilege: str) -> set[str]:
    rows = await conn.fetch(
        """
        SELECT column_name FROM information_schema.column_privileges
         WHERE grantee = $1 AND table_name = 'buzz_agents' AND privilege_type = $2
        """,
        role,
        privilege,
    )
    return {row["column_name"] for row in rows}


class TestGrants:
    async def test_mpass_role_reads_but_holds_no_table_wide_write(self, admin_conn):
        assert await table_privileges(admin_conn, "mpass_auth_user") == {"SELECT"}

    async def test_mpass_role_may_insert_only_the_enrollment_columns(self, admin_conn):
        assert await columns_with(admin_conn, "mpass_auth_user", "INSERT") == {
            "agent_pubkey", "owner_sub", "grant_hash", "grant_expires_at",
        }

    async def test_mpass_role_may_update_only_the_grant_and_revocation(self, admin_conn):
        assert await columns_with(admin_conn, "mpass_auth_user", "UPDATE") == {
            "grant_hash", "grant_expires_at", "revoked_at",
        }

    async def test_api_role_only_reads(self, admin_conn):
        assert await table_privileges(admin_conn, "launchpad_api_user") == {"SELECT"}
        assert await columns_with(admin_conn, "launchpad_api_user", "UPDATE") == set()
        assert await columns_with(admin_conn, "launchpad_api_user", "INSERT") == set()


class TestMpassRoleAtRuntime:
    async def test_enrolls_replaces_and_revokes(self, rolled_back):
        await as_role(rolled_back, "mpass_auth_user")
        agent = await enrolled_agent(rolled_back)
        replacement = new_grant_hash()

        await rolled_back.execute(REPLACE_GRANT_SQL, agent, replacement)
        assert await rolled_back.fetchval(
            "SELECT grant_hash FROM buzz_agents WHERE agent_pubkey = $1", agent
        ) == replacement

        assert await rolled_back.execute(REVOKE_SQL, agent) == "UPDATE 1"
        row = await rolled_back.fetchrow(
            "SELECT grant_hash, grant_expires_at, revoked_at FROM buzz_agents WHERE agent_pubkey = $1",
            agent,
        )
        assert row["grant_hash"] is None
        assert row["grant_expires_at"] is None
        assert row["revoked_at"] is not None

    async def test_revoking_again_matches_no_row(self, rolled_back):
        await as_role(rolled_back, "mpass_auth_user")
        agent = await revoked_agent(rolled_back)

        assert await rolled_back.execute(REVOKE_SQL, agent) == "UPDATE 0"

    @pytest.mark.parametrize("statement", [
        "UPDATE buzz_agents SET owner_sub = owner_sub WHERE agent_pubkey = $1",
        "UPDATE buzz_agents SET agent_pubkey = agent_pubkey WHERE agent_pubkey = $1",
        "UPDATE buzz_agents SET enrolled_at = now() WHERE agent_pubkey = $1",
        "DELETE FROM buzz_agents WHERE agent_pubkey = $1",
    ])
    async def test_cannot_move_backdate_or_erase(self, rolled_back, statement):
        await as_role(rolled_back, "mpass_auth_user")
        agent = await enrolled_agent(rolled_back)

        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await rolled_back.execute(statement, agent)

    @pytest.mark.parametrize("column, value", [
        ("revoked_at", "now()"),
        ("enrolled_at", "'2020-01-01'::timestamptz"),
    ])
    async def test_cannot_insert_pre_revoked_or_backdated_rows(self, rolled_back, column, value):
        await as_role(rolled_back, "mpass_auth_user")
        owner = await new_owner(rolled_back)

        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await rolled_back.execute(
                f"INSERT INTO buzz_agents (agent_pubkey, owner_sub, {column}) VALUES ($1, $2, {value})",
                new_pubkey(), owner,
            )

    async def test_api_role_cannot_write(self, rolled_back):
        owner = await new_owner(rolled_back)
        await as_role(rolled_back, "launchpad_api_user")

        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await rolled_back.execute(ENROLL_SQL, new_pubkey(), owner, new_grant_hash())


class TestConstraints:
    @pytest.mark.parametrize("pubkey", [
        "AB" * 32,
        "ab" * 31 + "a",
        "ab" * 32 + "a",
        "zz" * 32,
        "ab" * 32 + "\n",
        "",
    ])
    async def test_agent_pubkey_is_64_lowercase_hex(self, rolled_back, pubkey):
        owner = await new_owner(rolled_back)

        with pytest.raises(asyncpg.CheckViolationError):
            await rolled_back.execute(ENROLL_SQL, pubkey, owner, new_grant_hash())

    @pytest.mark.parametrize("grant_hash", ["AB" * 32, "ab" * 31, "not-a-hash", ""])
    async def test_grant_hash_is_a_lowercase_sha256_hex(self, rolled_back, grant_hash):
        owner = await new_owner(rolled_back)

        with pytest.raises(asyncpg.CheckViolationError):
            await rolled_back.execute(ENROLL_SQL, new_pubkey(), owner, grant_hash)

    async def test_owner_must_be_a_bound_identity(self, rolled_back):
        with pytest.raises(asyncpg.ForeignKeyViolationError):
            await rolled_back.execute(ENROLL_SQL, new_pubkey(), new_sub(), new_grant_hash())

    async def test_one_agent_key_has_one_row(self, rolled_back):
        agent = await enrolled_agent(rolled_back)

        with pytest.raises(asyncpg.UniqueViolationError):
            await rolled_back.execute(ENROLL_SQL, agent, await new_owner(rolled_back), new_grant_hash())

    async def test_a_grant_hash_names_one_agent(self, rolled_back):
        owner = await new_owner(rolled_back)
        grant_hash = new_grant_hash()
        await rolled_back.execute(ENROLL_SQL, new_pubkey(), owner, grant_hash)

        with pytest.raises(asyncpg.UniqueViolationError):
            await rolled_back.execute(ENROLL_SQL, new_pubkey(), owner, grant_hash)

    async def test_defaults(self, rolled_back):
        agent = await enrolled_agent(rolled_back)

        row = await rolled_back.fetchrow(
            "SELECT enrolled_at, revoked_at FROM buzz_agents WHERE agent_pubkey = $1", agent
        )
        assert row["enrolled_at"] is not None
        assert row["revoked_at"] is None

    async def test_owner_sub_is_indexed(self, admin_conn):
        assert await admin_conn.fetchval(
            "SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_buzz_agents_owner_sub'"
        ) is not None


class TestOwnerAndRevocationAreFinal:
    async def test_owner_cannot_change_even_for_the_table_owner(self, rolled_back):
        agent = await enrolled_agent(rolled_back)
        other_owner = await new_owner(rolled_back)

        with pytest.raises(asyncpg.RaiseError, match="belongs to its owner for good"):
            await rolled_back.execute(
                "UPDATE buzz_agents SET owner_sub = $2 WHERE agent_pubkey = $1", agent, other_owner
            )

    @pytest.mark.parametrize("role", ["mpass_auth_user", None])
    @pytest.mark.parametrize("new_value", ["NULL", "now() + interval '1 day'"])
    async def test_set_revoked_at_cannot_be_cleared_or_changed(self, rolled_back, role, new_value):
        if role:
            await as_role(rolled_back, role)
        agent = await revoked_agent(rolled_back)

        with pytest.raises(asyncpg.RaiseError, match="revocation of .* is final"):
            await rolled_back.execute(
                f"UPDATE buzz_agents SET revoked_at = {new_value} WHERE agent_pubkey = $1", agent
            )

    @pytest.mark.parametrize("role", ["mpass_auth_user", None])
    async def test_a_revoked_agent_cannot_be_enrolled_again(self, rolled_back, role):
        if role:
            await as_role(rolled_back, role)
        agent = await revoked_agent(rolled_back)

        with pytest.raises(asyncpg.RaiseError, match="cannot be enrolled again"):
            await rolled_back.execute(REPLACE_GRANT_SQL, agent, new_grant_hash())

    async def test_revoking_with_a_new_grant_in_one_statement_is_refused(self, rolled_back):
        agent = await enrolled_agent(rolled_back)

        with pytest.raises(asyncpg.CheckViolationError, match="buzz_agents_grant_while_active_check"):
            await rolled_back.execute(
                "UPDATE buzz_agents SET revoked_at = now(), grant_hash = $2 WHERE agent_pubkey = $1",
                agent, new_grant_hash(),
            )

    async def test_revoking_twice_with_the_same_value_is_a_no_op(self, rolled_back):
        await as_role(rolled_back, "mpass_auth_user")
        agent = await revoked_agent(rolled_back)

        await rolled_back.execute(
            "UPDATE buzz_agents SET revoked_at = revoked_at, grant_hash = NULL WHERE agent_pubkey = $1",
            agent,
        )

    async def test_reapplying_the_schema_keeps_exactly_one_trigger(self, admin_conn):
        schema = migrate.SCHEMA_PATH.read_text()
        await migrate.apply_schema(TEST_ADMIN_DSN, schema)
        await migrate.apply_schema(TEST_ADMIN_DSN, schema)

        triggers = await admin_conn.fetch(
            """
            SELECT tgname FROM pg_trigger
             WHERE tgrelid = 'buzz_agents'::regclass AND NOT tgisinternal
            """
        )
        assert [row["tgname"] for row in triggers] == [TRIGGER_NAME]

    async def test_reapplying_the_schema_leaves_the_trigger_in_place(self, admin_conn):
        trigger_oid_sql = """
            SELECT oid FROM pg_trigger
             WHERE tgrelid = 'buzz_agents'::regclass AND tgname = $1
        """
        before = await admin_conn.fetchval(trigger_oid_sql, TRIGGER_NAME)

        await migrate.apply_schema(TEST_ADMIN_DSN, migrate.SCHEMA_PATH.read_text())

        assert await admin_conn.fetchval(trigger_oid_sql, TRIGGER_NAME) == before


class TestGrantCompleteness:
    async def test_a_grant_hash_needs_an_expiry(self, rolled_back):
        owner = await new_owner(rolled_back)

        with pytest.raises(asyncpg.CheckViolationError, match="buzz_agents_grant_has_expiry_check"):
            await rolled_back.execute(
                "INSERT INTO buzz_agents (agent_pubkey, owner_sub, grant_hash) VALUES ($1, $2, $3)",
                new_pubkey(), owner, new_grant_hash(),
            )

    async def test_revoking_must_drop_the_grant(self, rolled_back):
        agent = await enrolled_agent(rolled_back)

        with pytest.raises(asyncpg.CheckViolationError, match="buzz_agents_grant_while_active_check"):
            await rolled_back.execute(
                "UPDATE buzz_agents SET revoked_at = now() WHERE agent_pubkey = $1", agent
            )

    async def test_an_active_agent_must_hold_a_grant(self, rolled_back):
        agent = await enrolled_agent(rolled_back)

        with pytest.raises(asyncpg.CheckViolationError, match="buzz_agents_grant_while_active_check"):
            await rolled_back.execute(
                "UPDATE buzz_agents SET grant_hash = NULL, grant_expires_at = NULL WHERE agent_pubkey = $1",
                agent,
            )


# The statements mpass-auth-proxy runs (nip_fa/agents.py), copied verbatim so a
# schema or grant change that breaks them fails here first.
PROXY_LOCK_OWNER_SQL = "SELECT pubkey_hex, revoked_at FROM buzz_identities WHERE sub = $1 FOR NO KEY UPDATE"
PROXY_IS_IDENTITY_KEY_SQL = "SELECT EXISTS (SELECT 1 FROM buzz_identities WHERE pubkey_hex = $1)"
PROXY_EXISTING_AGENT_SQL = "SELECT owner_sub, revoked_at FROM buzz_agents WHERE agent_pubkey = $1"
PROXY_OTHER_ACTIVE_AGENTS_SQL = (
    "SELECT count(*) FROM buzz_agents WHERE owner_sub = $1 AND revoked_at IS NULL AND agent_pubkey <> $2"
)
PROXY_ENROLL_SQL = (
    "INSERT INTO buzz_agents (agent_pubkey, owner_sub, grant_hash, grant_expires_at) "
    "VALUES ($1, $2, $3, $4) "
    "ON CONFLICT (agent_pubkey) DO UPDATE "
    "SET grant_hash = EXCLUDED.grant_hash, grant_expires_at = EXCLUDED.grant_expires_at "
    "WHERE buzz_agents.owner_sub = EXCLUDED.owner_sub AND buzz_agents.revoked_at IS NULL "
    "RETURNING agent_pubkey"
)
PROXY_GRANT_SQL = (
    "SELECT a.agent_pubkey, a.owner_sub, a.grant_expires_at, a.revoked_at, "
    "i.pubkey_hex AS owner_pubkey, i.revoked_at AS owner_revoked_at "
    "FROM buzz_agents a JOIN buzz_identities i ON i.sub = a.owner_sub "
    "WHERE a.grant_hash = $1"
)
PROXY_REVOKE_SQL = (
    "UPDATE buzz_agents SET revoked_at = now(), grant_hash = NULL, grant_expires_at = NULL "
    "WHERE agent_pubkey = $1 AND owner_sub = $2 AND revoked_at IS NULL "
    "RETURNING agent_pubkey"
)
PROXY_OWNED_AGENT_SQL = "SELECT revoked_at FROM buzz_agents WHERE agent_pubkey = $1 AND owner_sub = $2"


def in_eight_days() -> datetime:
    return datetime.now(UTC) + timedelta(days=8)


async def proxy_enroll(conn: asyncpg.Connection, agent: str, owner: str, grant_hash: str):
    return await conn.fetchval(PROXY_ENROLL_SQL, agent, owner, grant_hash, in_eight_days())


class TestProxyStatements:
    async def test_locks_the_owner_row(self, rolled_back):
        owner = await new_owner(rolled_back)
        await as_role(rolled_back, "mpass_auth_user")

        row = await rolled_back.fetchrow(PROXY_LOCK_OWNER_SQL, owner)

        assert row["revoked_at"] is None

    async def test_runs_the_enrollment_checks(self, rolled_back):
        owner = await new_owner(rolled_back)
        owner_pubkey = await rolled_back.fetchval("SELECT pubkey_hex FROM buzz_identities WHERE sub = $1", owner)
        agent = await enrolled_agent(rolled_back, owner)
        await as_role(rolled_back, "mpass_auth_user")

        assert await rolled_back.fetchval(PROXY_IS_IDENTITY_KEY_SQL, owner_pubkey) is True
        assert await rolled_back.fetchval(PROXY_IS_IDENTITY_KEY_SQL, agent) is False
        assert (await rolled_back.fetchrow(PROXY_EXISTING_AGENT_SQL, agent))["owner_sub"] == owner
        assert await rolled_back.fetchval(PROXY_OTHER_ACTIVE_AGENTS_SQL, owner, agent) == 0
        assert await rolled_back.fetchval(PROXY_OTHER_ACTIVE_AGENTS_SQL, owner, new_pubkey()) == 1

    async def test_enrolls_then_replaces_the_grant(self, rolled_back):
        owner = await new_owner(rolled_back)
        agent = new_pubkey()
        await as_role(rolled_back, "mpass_auth_user")

        assert await proxy_enroll(rolled_back, agent, owner, new_grant_hash()) == agent
        replacement = new_grant_hash()
        assert await proxy_enroll(rolled_back, agent, owner, replacement) == agent
        assert (await rolled_back.fetchrow(PROXY_GRANT_SQL, replacement))["agent_pubkey"] == agent

    async def test_another_owner_cannot_take_the_agent(self, rolled_back):
        first, second = await new_owner(rolled_back), await new_owner(rolled_back)
        agent = new_pubkey()
        await as_role(rolled_back, "mpass_auth_user")
        original = new_grant_hash()
        await proxy_enroll(rolled_back, agent, first, original)

        assert await proxy_enroll(rolled_back, agent, second, new_grant_hash()) is None
        row = await rolled_back.fetchrow(PROXY_GRANT_SQL, original)
        assert row["owner_sub"] == first

    async def test_a_revoked_agent_is_not_enrolled_again(self, rolled_back):
        owner = await new_owner(rolled_back)
        agent = new_pubkey()
        await as_role(rolled_back, "mpass_auth_user")
        await proxy_enroll(rolled_back, agent, owner, new_grant_hash())
        await rolled_back.fetchval(PROXY_REVOKE_SQL, agent, owner)

        assert await proxy_enroll(rolled_back, agent, owner, new_grant_hash()) is None
        assert (await rolled_back.fetchrow(PROXY_OWNED_AGENT_SQL, agent, owner))["revoked_at"] is not None

    async def test_reads_a_grant_with_its_owner(self, rolled_back):
        owner = await new_owner(rolled_back)
        grant_hash = new_grant_hash()
        agent = new_pubkey()
        await as_role(rolled_back, "mpass_auth_user")
        await proxy_enroll(rolled_back, agent, owner, grant_hash)

        row = await rolled_back.fetchrow(PROXY_GRANT_SQL, grant_hash)

        assert row["agent_pubkey"] == agent
        assert row["owner_sub"] == owner
        assert row["owner_pubkey"] == (await rolled_back.fetchrow(PROXY_LOCK_OWNER_SQL, owner))["pubkey_hex"]
        assert row["grant_expires_at"] is not None
        assert row["revoked_at"] is None
        assert row["owner_revoked_at"] is None

    async def test_revokes_only_the_owners_own_agent_once(self, rolled_back):
        owner, stranger = await new_owner(rolled_back), await new_owner(rolled_back)
        agent = new_pubkey()
        grant_hash = new_grant_hash()
        await as_role(rolled_back, "mpass_auth_user")
        await proxy_enroll(rolled_back, agent, owner, grant_hash)

        assert await rolled_back.fetchval(PROXY_REVOKE_SQL, agent, stranger) is None
        assert await rolled_back.fetchrow(PROXY_OWNED_AGENT_SQL, agent, stranger) is None
        assert await rolled_back.fetchval(PROXY_REVOKE_SQL, agent, owner) == agent
        assert await rolled_back.fetchval(PROXY_REVOKE_SQL, agent, owner) is None
        assert await rolled_back.fetchrow(PROXY_GRANT_SQL, grant_hash) is None
