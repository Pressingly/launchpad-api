"""PRD-H part B — correcting your own address while a verification is pending.

The commonest cause of a verification email never arriving is a typo, and
without a way to fix it the user is stuck with the address they mistyped until
an operator runs the override. Part B is what actually reduces lockouts today:
unlike part A it needs no relink mechanism to be useful.

**No endpoint was added.** `POST /api/email` already handles resubmission, and
these tests are the check the PRD asks for -- that it replaces the pending
address, kills the old link, leaves nothing claimed on the old address, and
charges an existing rate-limit bucket rather than offering a way around one.
They are written as behaviour tests, not as a description of the current
implementation, so a future change that quietly breaks any of the four fails
here.
"""
import pytest

from src import db
from src.config import settings
from tests.conftest import (
    audit_actions,
    latest_token,
    mailpit_clear,
    mailpit_messages,
    new_email,
    new_sid,
    seed_relinked,
    submit,
)

pytestmark = pytest.mark.usefixtures("cleanup_test_users")


async def test_correcting_the_address_replaces_it_and_kills_the_old_link(
    raw_client, clean_mailbox
):
    sid = new_sid()
    typo, fixed = new_email("typo"), new_email("fixed")

    assert (await submit(raw_client, sid, typo)).status_code == 202
    old_token = await latest_token()
    await mailpit_clear()

    assert (await submit(raw_client, sid, fixed)).status_code == 202

    user = await db.fetch_user(sid)
    assert user["real_email"] == fixed
    assert user["verified"] is False

    # The new link works...
    new_token = await latest_token()
    assert new_token != old_token
    ok = await raw_client.get(f"/api/verify?token={new_token}", follow_redirects=False)
    assert "relinking=1" in ok.headers["location"]


async def test_the_old_token_no_longer_verifies(raw_client, clean_mailbox):
    """...and the old one is dead.

    It has to be. The old link was emailed to the address the user does NOT
    control (that is what "typo" means), so leaving it live would let whoever
    does control it complete a verification for somebody else's account.
    """
    sid = new_sid()
    assert (await submit(raw_client, sid, new_email("stale"))).status_code == 202
    old_token = await latest_token()

    assert (await submit(raw_client, sid, new_email("current"))).status_code == 202

    dead = await raw_client.get(
        f"/api/verify?token={old_token}", follow_redirects=False
    )
    assert dead.status_code == 302
    assert "verify_error=expired_or_invalid" in dead.headers["location"]

    user = await db.fetch_user(sid)
    assert user["verified"] is False
    assert user["relink_state"] == "none"


async def test_the_mistyped_address_is_not_left_claimed(raw_client, clean_mailbox):
    """Its real owner must still be able to register it afterwards.

    Two mechanisms make this true and both are load-bearing: the row is updated
    in place rather than a second row being inserted, and idx_foss_users_email
    is partial (`WHERE verified`), so even a lingering unverified claim would
    not block anyone. Assert it through the real path -- all the way to
    mark_relinked, which is the statement the unique index fires on.
    """
    mistyper = new_sid()
    contested = new_email("contested")

    assert (await submit(raw_client, mistyper, contested)).status_code == 202
    assert (await submit(raw_client, mistyper, new_email("corrected"))).status_code == 202

    owner = new_sid()
    assert (await submit(raw_client, owner, contested)).status_code == 202
    token = await latest_token()
    clicked = await raw_client.get(
        f"/api/verify?token={token}", follow_redirects=False
    )
    assert "relinking=1" in clicked.headers["location"]
    # All the way to mark_relinked: that UPDATE is the statement
    # idx_foss_users_email fires on, so anything still claiming the address
    # would surface here as EmailAlreadyRegistered.
    assert await db.mark_relinked(owner) is True
    assert (await db.fetch_user(owner))["real_email"] == contested
    assert (await db.fetch_user(owner))["verified"] is True


async def test_correcting_charges_the_rate_limit_bucket(raw_client, clean_mailbox):
    """Correcting an address must not be a way around the endpoint's anti-abuse
    control.

    A *different* address routes to the `submit` bucket (a repeat of the address
    the caller already holds routes to the far smaller `resend` bucket instead --
    see main.submit_email). Both are pre-existing buckets; the requirement is
    that one of them is charged, and this asserts the corrections are what
    exhaust it.
    """
    sid = new_sid()
    limit = settings.rate_limit_submit_per_hour

    for i in range(limit):
        last_accepted = new_email(f"burn{i}")
        assert (await submit(raw_client, sid, last_accepted)).status_code == 202

    over = new_email("one-too-many")
    refused = await submit(raw_client, sid, over)
    assert refused.status_code == 429
    assert "Retry-After" in refused.headers

    # And the refusal did not quietly apply the change anyway. Compare against
    # the address actually submitted: new_email() appends a random suffix, so a
    # comparison with the bare "one-too-many" literal can never fail and would
    # pass even if the 429 path wrote the row.
    assert (await db.fetch_user(sid))["real_email"] == last_accepted
    assert (await db.fetch_user(sid))["real_email"] != over


async def test_the_audit_trail_shows_both_submissions(raw_client, clean_mailbox):
    """The compliance record must show the user consented to each address, not
    just the one they ended up with."""
    sid = new_sid()
    first, second = new_email("first"), new_email("second")

    await submit(raw_client, sid, first)
    await submit(raw_client, sid, second)

    assert await audit_actions(sid) == ["submit_email", "submit_email"]

    pool = await db.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT email, consent_text_version FROM foss_users_audit "
            "WHERE synthetic_id = $1 ORDER BY id",
            sid,
        )
    assert [r["email"] for r in rows] == [first, second]
    assert all(r["consent_text_version"] for r in rows)


async def test_correcting_after_clicking_the_link_returns_to_pending_verification(
    raw_client, clean_mailbox
):
    """A user in pending_relink who resubmits is reset to a fresh verification.

    This is PRD-G's behaviour, asserted here rather than added: submit_email's
    ON CONFLICT branch sets `relink_state = 'none'` because a fresh submission
    starts the flow over and the address it was relinking has just changed.
    Leaving it in pending_relink would queue a relink onto an address the user
    abandoned.

    Note the portal deliberately offers no control that reaches this state --
    the relinking panel has no resubmit button, by design (PRD-G) -- so this is
    the API's behaviour for a caller that gets here some other way, not a flow
    the UI invites.
    """
    sid = new_sid()
    await submit(raw_client, sid, new_email("clicked"))
    token = await latest_token()
    await raw_client.get(f"/api/verify?token={token}", follow_redirects=False)
    assert (await db.fetch_user(sid))["relink_state"] == "pending_relink"

    corrected = new_email("clicked-fix")
    assert (await submit(raw_client, sid, corrected)).status_code == 202

    user = await db.fetch_user(sid)
    assert user["real_email"] == corrected
    assert user["relink_state"] == "none"
    assert user["verified"] is False
    assert user["verification_token"] is not None


async def test_a_verified_user_cannot_change_their_own_address(raw_client):
    """Part B is for PENDING users only.

    A relink-complete user's address is live in every app, so letting them swap
    it from the portal would strand their content in exactly the way the gate
    exists to prevent. That change goes through the operator override, which is
    why this stays a 409.
    """
    sid, live = new_sid(), new_email("settled")
    await seed_relinked(sid, live)

    resp = await submit(raw_client, sid, new_email("wanted"))
    assert resp.status_code == 409
    assert (await db.fetch_user(sid))["real_email"] == live


async def test_a_correction_sends_to_the_new_address_only(raw_client, clean_mailbox):
    sid = new_sid()
    await submit(raw_client, sid, new_email("wrong"))
    await mailpit_clear()

    right = new_email("right")
    await submit(raw_client, sid, right)

    messages = await mailpit_messages()
    assert len(messages) == 1
    recipients = [t["Address"] for t in messages[0]["To"]]
    assert recipients == [right]
