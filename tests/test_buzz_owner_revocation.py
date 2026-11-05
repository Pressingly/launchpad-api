"""Owner revocation as mpass-auth-proxy runs it (nip_fa/revocation.py): the
statements are copied verbatim and run as mpass_auth_user, so a schema or
grant change that breaks revocation, its effect on agent grants, or the relay
deny re-push fails here first."""
from datetime import timedelta

import asyncpg

from tests.test_buzz_agents import (
    PROXY_GRANT_SQL,
    PROXY_LOCK_OWNER_SQL,
    PROXY_REVOKE_SQL,
    new_grant_hash,
    new_owner,
    proxy_enroll,
)
from tests.test_buzz_identities import (
    as_role,
    new_pubkey,
    new_sub,
    rolled_back,  # noqa: F401  (fixture applies by import)
)

PROXY_REVOKE_IDENTITY_SQL = (
    "UPDATE buzz_identities SET revoked_at = now() WHERE sub = $1 AND revoked_at IS NULL "
    "RETURNING pubkey_hex, revoked_at"
)
PROXY_IDENTITY_SQL = "SELECT pubkey_hex, revoked_at FROM buzz_identities WHERE sub = $1"
PROXY_RECENT_REVOCATIONS_SQL = (
    "SELECT pubkey_hex AS pubkey, revoked_at FROM buzz_identities "
    "WHERE revoked_at > now() - make_interval(secs => $1) "
    "UNION ALL "
    "SELECT agent_pubkey AS pubkey, revoked_at FROM buzz_agents "
    "WHERE revoked_at > now() - make_interval(secs => $1)"
)
DENY_WINDOW_SECONDS = 300.0


async def owner_pubkey(conn: asyncpg.Connection, sub: str) -> str:
    return (await conn.fetchrow(PROXY_IDENTITY_SQL, sub))["pubkey_hex"]


async def recent_pubkeys(conn: asyncpg.Connection) -> set[str]:
    rows = await conn.fetch(PROXY_RECENT_REVOCATIONS_SQL, DENY_WINDOW_SECONDS)
    return {row["pubkey"] for row in rows}


class TestOwnerRevocation:
    async def test_revokes_an_active_identity(self, rolled_back):
        owner = await new_owner(rolled_back)
        await as_role(rolled_back, "mpass_auth_user")

        revoked = await rolled_back.fetchrow(PROXY_REVOKE_IDENTITY_SQL, owner)

        assert revoked["pubkey_hex"] == await owner_pubkey(rolled_back, owner)
        assert (await rolled_back.fetchrow(PROXY_IDENTITY_SQL, owner))["revoked_at"] == revoked["revoked_at"]

    async def test_a_repeat_keeps_the_first_revocation_time(self, rolled_back):
        owner = await new_owner(rolled_back)
        first = await rolled_back.fetchval(
            "UPDATE buzz_identities SET revoked_at = now() - interval '1 hour' WHERE sub = $1 RETURNING revoked_at",
            owner,
        )
        await as_role(rolled_back, "mpass_auth_user")

        assert await rolled_back.fetchrow(PROXY_REVOKE_IDENTITY_SQL, owner) is None
        assert (await rolled_back.fetchrow(PROXY_IDENTITY_SQL, owner))["revoked_at"] == first

    async def test_an_unbound_subject_has_nothing_to_revoke(self, rolled_back):
        await as_role(rolled_back, "mpass_auth_user")
        assert await rolled_back.fetchrow(PROXY_REVOKE_IDENTITY_SQL, new_sub()) is None
        assert await rolled_back.fetchrow(PROXY_IDENTITY_SQL, new_sub()) is None

    async def test_ends_every_grant_the_owner_authorized(self, rolled_back):
        owner = await new_owner(rolled_back)
        await as_role(rolled_back, "mpass_auth_user")
        grant_hashes = [new_grant_hash(), new_grant_hash()]
        for grant_hash in grant_hashes:
            await proxy_enroll(rolled_back, new_pubkey(), owner, grant_hash)

        await rolled_back.fetchrow(PROXY_REVOKE_IDENTITY_SQL, owner)

        for grant_hash in grant_hashes:
            assert (await rolled_back.fetchrow(PROXY_GRANT_SQL, grant_hash))["owner_revoked_at"] is not None
        assert (await rolled_back.fetchrow(PROXY_LOCK_OWNER_SQL, owner))["revoked_at"] is not None


class TestRecentRevocations:
    async def test_lists_recently_revoked_owner_and_agent_keys(self, rolled_back):
        owner, agent_owner = await new_owner(rolled_back), await new_owner(rolled_back)
        await as_role(rolled_back, "mpass_auth_user")
        agent = new_pubkey()
        await proxy_enroll(rolled_back, agent, agent_owner, new_grant_hash())
        await proxy_enroll(rolled_back, new_pubkey(), agent_owner, new_grant_hash())
        await rolled_back.fetchrow(PROXY_REVOKE_IDENTITY_SQL, owner)
        await rolled_back.fetchval(PROXY_REVOKE_SQL, agent, agent_owner)

        pubkeys = await recent_pubkeys(rolled_back)

        assert await owner_pubkey(rolled_back, owner) in pubkeys
        assert agent in pubkeys
        assert await owner_pubkey(rolled_back, agent_owner) not in pubkeys

    async def test_skips_revocations_older_than_the_window(self, rolled_back):
        owner, agent_owner = await new_owner(rolled_back), await new_owner(rolled_back)
        agent = new_pubkey()
        await proxy_enroll(rolled_back, agent, agent_owner, new_grant_hash())
        too_old = timedelta(seconds=DENY_WINDOW_SECONDS + 1)
        await rolled_back.execute(
            "UPDATE buzz_identities SET revoked_at = now() - $2::interval WHERE sub = $1", owner, too_old
        )
        await rolled_back.execute(
            "UPDATE buzz_agents SET revoked_at = now() - $2::interval, grant_hash = NULL, grant_expires_at = NULL "
            "WHERE agent_pubkey = $1",
            agent, too_old,
        )
        await as_role(rolled_back, "mpass_auth_user")

        recent = await recent_pubkeys(rolled_back)
        assert await owner_pubkey(rolled_back, owner) not in recent
        assert agent not in recent
