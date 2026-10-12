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
from src.config import RELINK_SKIP, settings
from tests.conftest import (
    audit_actions,
    latest_token,
    mailpit_clear,
    mailpit_messages,
    new_email,
    new_sid,
    relink_state,
    seed_pending,
    seed_relinked,
    sha256_hex,
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


async def test_correcting_after_clicking_the_link_is_refused(raw_client, clean_mailbox):
    """Clicking the link holds the user at pending_relink, and only the operator
    override releases them. The portal offers no resubmit control there; this
    is the API refusing a caller who POSTs anyway."""
    sid, clicked = new_sid(), new_email("clicked")
    await submit(raw_client, sid, clicked)
    token = await latest_token()
    await raw_client.get(f"/api/verify?token={token}", follow_redirects=False)
    assert (await db.fetch_user(sid))["relink_state"] == "pending_relink"

    assert (await submit(raw_client, sid, new_email("clicked-fix"))).status_code == 409

    user = await db.fetch_user(sid)
    assert user["real_email"] == clicked
    assert user["relink_state"] == "pending_relink"
    assert user["verified"] is False
    assert user["verification_token"] is None


HELD_ERRORS = {"pending_relink": "relink_in_progress", "relink_failed": "relink_failed"}


async def _hold(sid: str, state: str, verified: bool = False) -> None:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE foss_users SET relink_state = $2, verified = $3 WHERE synthetic_id = $1",
            sid, state, verified,
        )


async def resend(ac, sid: str):
    return await ac.post(
        "/api/email/resend", headers={"X-Auth-Request-Preferred-Username": sid}
    )


async def _assert_hold_untouched(sid: str, held_email: str, held_state: str, raw_token: str):
    user = await db.fetch_user(sid)
    assert user["real_email"] == held_email
    assert user["relink_state"] == held_state
    assert user["verified"] is False
    assert user["verification_token"] == sha256_hex(raw_token)
    assert await audit_actions(sid) == []
    assert await mailpit_messages() == []


@pytest.mark.parametrize("mode", ["manual", RELINK_SKIP])
@pytest.mark.parametrize("held_state", ["pending_relink", "relink_failed"])
async def test_a_held_user_cannot_resubmit_their_way_out_of_the_hold(
    raw_client, clean_mailbox, monkeypatch, mode, held_state
):
    monkeypatch.setattr(settings, "launchpad_relink_runner", mode)
    sid, held = new_sid(), new_email("held")
    await seed_pending(sid, held, "tok-held")
    await _hold(sid, held_state)

    response = await submit(raw_client, sid, new_email("escape"))

    assert response.status_code == 409
    assert response.json()["error"] == HELD_ERRORS[held_state]
    await _assert_hold_untouched(sid, held, held_state, "tok-held")


@pytest.mark.parametrize("mode", ["manual", RELINK_SKIP])
@pytest.mark.parametrize("held_state", ["pending_relink", "relink_failed"])
async def test_a_held_user_cannot_resend_their_way_out_of_the_hold(
    raw_client, clean_mailbox, monkeypatch, mode, held_state
):
    monkeypatch.setattr(settings, "launchpad_relink_runner", mode)
    sid, held = new_sid(), new_email("held-resend")
    await seed_pending(sid, held, "tok-held-resend")
    await _hold(sid, held_state)

    response = await resend(raw_client, sid)

    assert response.status_code == 409
    assert response.json()["error"] == HELD_ERRORS[held_state]
    await _assert_hold_untouched(sid, held, held_state, "tok-held-resend")


@pytest.mark.parametrize("endpoint", ["submit", "resend"])
async def test_an_interrupted_override_reports_the_hold_not_verified(
    raw_client, clean_mailbox, endpoint
):
    """(verified, pending_relink) is held to /api/me and the gate, so both
    endpoints say held too."""
    sid = new_sid()
    await seed_pending(sid, new_email("interrupted"), "tok-interrupted")
    await _hold(sid, "pending_relink", verified=True)

    if endpoint == "submit":
        response = await submit(raw_client, sid, new_email("interrupted-escape"))
    else:
        response = await resend(raw_client, sid)

    assert response.status_code == 409
    assert response.json()["error"] == "relink_in_progress"


@pytest.mark.parametrize("held_state", ["pending_relink", "relink_failed"])
async def test_under_skip_a_held_user_cannot_complete_through_any_link(
    raw_client, clean_mailbox, monkeypatch, held_state
):
    """The FOSS-510 path end to end: resubmit or resend, then click. Neither
    the link the user already holds nor a fresh one may complete a held row."""
    monkeypatch.setattr(settings, "launchpad_relink_runner", RELINK_SKIP)
    sid = new_sid()
    await seed_pending(sid, new_email("held-skip"), "tok-held-skip")
    await _hold(sid, held_state)

    assert (await submit(raw_client, sid, new_email("held-skip-escape"))).status_code == 409
    assert (await resend(raw_client, sid)).status_code == 409
    assert await mailpit_messages() == []
    response = await raw_client.get("/api/verify?token=tok-held-skip", follow_redirects=False)
    assert "verify_error=expired_or_invalid" in response.headers["location"]

    user = await db.fetch_user(sid)
    assert user["verified"] is False
    assert user["relink_state"] == held_state


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


async def test_correcting_the_address_evicts_the_gate_memo(raw_client):
    """gate.evict's contract is unconditional: every transition that changes a
    memoized field evicts, and the memo carries the address."""
    from src import gate

    sid, first = new_sid(), new_email("evict-pending")
    await seed_pending(sid, first, "tok-evict-pending")
    _, email, _ = await gate.verified_state(sid, ttl_seconds=300)
    assert email == first, "memo must be primed for the test to mean anything"

    corrected = new_email("evict-corrected")
    response = await submit(raw_client, sid, corrected)
    assert response.status_code == 202

    _, after, _ = await gate.verified_state(sid, ttl_seconds=300)
    assert after == corrected
