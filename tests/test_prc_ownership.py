"""PRD §6.1 — Ownership / squatting.

After §1.1 the unique index on real_email is partial (`WHERE verified`), so an
unverified claim on an address is non-binding: two accounts may hold the same
pending address, and exclusivity is decided at *verification* time.
"""
from src import db
from tests.conftest import new_email, new_sid, seed_pending, submit


async def test_two_accounts_may_hold_same_unverified_address(client, cleanup_test_users):
    """Both submits return 202 — an unverified claim blocks nobody (§1.1)."""
    email = new_email("squat")
    sid1, sid2 = new_sid(), new_sid()

    first = await submit(client, sid1, email)
    second = await submit(client, sid2, email)

    assert first.status_code == 202
    assert second.status_code == 202

    assert (await db.fetch_user(sid1))["real_email"] == email
    assert (await db.fetch_user(sid2))["real_email"] == email


async def test_second_verify_of_taken_address_redirects_email_taken(
    raw_client, cleanup_test_users
):
    """The relocated conflict (§3.4): the loser gets a redirect, never a 500."""
    email = new_email("taken")
    sid1, sid2 = new_sid(), new_sid()
    await seed_pending(sid1, email, "tok-winner")
    await seed_pending(sid2, email, "tok-loser")

    winner = await raw_client.get("/api/verify?token=tok-winner", follow_redirects=False)
    assert winner.status_code == 302
    assert "relinking=1" in winner.headers["location"]
    # The winner must be relink-COMPLETE before the address is exclusive: the
    # partial index covers verified rows only, and clicking the link no longer
    # sets verified. This is why mark_pending_relink keeps its own probe --
    # without it the loser would sit in pending_relink waiting for a relink
    # that can never complete.
    assert await db.mark_relinked(sid1) is True

    loser = await raw_client.get("/api/verify?token=tok-loser", follow_redirects=False)
    assert loser.status_code != 500, "a legitimate link must never 500 (§3.4)"
    assert loser.status_code == 302
    assert "verify_error=email_taken" in loser.headers["location"]


async def test_verified_address_blocks_a_second_verification(raw_client, cleanup_test_users):
    """The partial index still does its job: only one row per verified address."""
    email = new_email("excl")
    sid1, sid2 = new_sid(), new_sid()
    await seed_pending(sid1, email, "tok-first")
    await seed_pending(sid2, email, "tok-second")

    await raw_client.get("/api/verify?token=tok-first", follow_redirects=False)
    assert await db.mark_relinked(sid1) is True
    await raw_client.get("/api/verify?token=tok-second", follow_redirects=False)

    assert (await db.fetch_user(sid1))["verified"] is True
    assert (await db.fetch_user(sid2))["verified"] is False

    pool = await db.get_pool()
    async with pool.acquire() as conn:
        verified_count = await conn.fetchval(
            "SELECT count(*) FROM foss_users WHERE real_email = $1 AND verified", email
        )
    assert verified_count == 1
