"""PRD-H part A — the operator unblock (`src/ops_override.py`).

The interesting assertions here are the refusals. Completing a relink that has
not happened is not a smaller version of the override, it is the duplicate-
account bug the gate exists to prevent, shipped behind a CLI -- so the three
LAUNCHPAD_RELINK_RUNNER cases each get a test that also proves *nothing was
written* on the refusing paths.
"""
import pytest

from src import db, gate
from src.config import Settings, settings
from src.ops_override import OverrideRefused, run_override
from tests.conftest import (
    new_email,
    new_sid,
    seed_pending,
    seed_relinked,
    sha256_hex,
)

pytestmark = pytest.mark.usefixtures("cleanup_test_users")


async def _audit_rows(sid: str) -> list:
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT action, email, consent_text_version, consent_text_content, "
            "user_agent FROM foss_users_audit WHERE synthetic_id = $1 ORDER BY id",
            sid,
        )
    return [dict(r) for r in rows]


async def _override(sid, email, **kw):
    kw.setdefault("reason", "FOSS-13: mail bounces at the user's provider")
    kw.setdefault("operator", "opsuser@bastion")
    return await run_override(synthetic_id=sid, email=email, **kw)


# ---------------------------------------------------------------------------
# The variable the whole command branches on
# ---------------------------------------------------------------------------


def test_the_runner_setting_binds_to_the_env_var_compose_actually_sets(monkeypatch):
    """LAUNCHPAD_RELINK_RUNNER, not RELINK_RUNNER.

    config.py sets env_prefix = "", so the field name IS the variable name. A
    field called `relink_runner` would read empty in the container and the
    override would then refuse every invocation -- which is indistinguishable
    from the override refusing correctly, so it would be diagnosed as policy
    rather than as a typo. Every other test in this file passes `runner=`
    explicitly and would not notice.
    """
    monkeypatch.setenv("LAUNCHPAD_RELINK_RUNNER", "manual")
    assert Settings().launchpad_relink_runner == "manual"


def test_the_runner_setting_is_trimmed_like_platform_sh_trims_it(monkeypatch):
    """`_rendered_value` in platform.sh trims whitespace before matching, so a
    trailing space must not make the two sides disagree about validity."""
    monkeypatch.setenv("LAUNCHPAD_RELINK_RUNNER", "  runner  ")
    assert Settings().launchpad_relink_runner == "runner"


async def test_run_override_reads_the_setting_when_no_runner_is_passed(monkeypatch):
    """The CLI passes nothing; the environment decides."""
    monkeypatch.setattr(settings, "launchpad_relink_runner", "", raising=False)
    with pytest.raises(OverrideRefused) as exc:
        await _override(new_sid(), new_email("envread"))
    assert "LAUNCHPAD_RELINK_RUNNER is empty" in str(exc.value)


# ---------------------------------------------------------------------------
# Case 1 of 3 — empty: refuse
# ---------------------------------------------------------------------------


async def test_empty_runner_refuses_and_names_the_consequence():
    sid, email = new_sid(), new_email("empty")
    await seed_pending(sid, email, "tok-empty")

    with pytest.raises(OverrideRefused) as exc:
        await _override(sid, new_email("empty-new"), runner="")

    message = str(exc.value)
    assert "LAUNCHPAD_RELINK_RUNNER is empty" in message
    # The message has to say what completing would DO, not just that it is
    # refused: the operator is holding a locked-out user and needs to know that
    # the command they reached for would have made it worse.
    assert "SECOND" in message
    assert "strand" in message

    # Nothing written, on either table.
    user = await db.fetch_user(sid)
    assert user["real_email"] == email
    assert user["verified"] is False
    assert user["relink_state"] == "none"
    assert await _audit_rows(sid) == []


async def test_empty_runner_refuses_even_with_relink_done():
    """--relink-done is not a way past the empty case. There is no mechanism to
    have used, so the assertion cannot be true."""
    sid, email = new_sid(), new_email("emptyflag")
    await seed_pending(sid, email, "tok-emptyflag")

    with pytest.raises(OverrideRefused):
        await _override(sid, new_email("emptyflag-new"), runner="", relink_done=True)

    assert (await db.fetch_user(sid))["verified"] is False


async def test_an_unrecognised_runner_value_refuses():
    """Same vocabulary as platform.sh, matched the same way: exact and
    case-sensitive. A typo that read as 'manual' would complete relinks nobody
    performed."""
    sid = new_sid()
    await seed_pending(sid, new_email("typo"), "tok-typo")

    for value in ("Manual", "MANUAL", "runners", "true"):
        with pytest.raises(OverrideRefused) as exc:
            await _override(sid, new_email("typo-new"), runner=value, relink_done=True)
        assert "not a value this platform understands" in str(exc.value)

    assert (await db.fetch_user(sid))["verified"] is False
    assert await _audit_rows(sid) == []


# ---------------------------------------------------------------------------
# Case 2 of 3 — manual: require --relink-done
# ---------------------------------------------------------------------------


async def test_manual_without_relink_done_refuses_and_prints_the_assertion():
    sid, email = new_sid(), new_email("manual")
    await seed_pending(sid, email, "tok-manual")

    with pytest.raises(OverrideRefused) as exc:
        await _override(sid, new_email("manual-new"), runner="manual")

    message = str(exc.value)
    assert "--relink-done" in message
    # What the flag asserts, in the refusal itself -- an operator who is told
    # only "add --relink-done" adds it.
    assert "by hand" in message
    assert "SECOND account" in message

    assert (await db.fetch_user(sid))["verified"] is False
    assert await _audit_rows(sid) == []


async def test_manual_with_relink_done_sets_the_email_and_completes():
    sid, old_email = new_sid(), new_email("manual-old")
    new = new_email("manual-new")
    await seed_pending(sid, old_email, "tok-manual-ok")

    message = await _override(sid, new, runner="manual", relink_done=True)
    assert new in message

    user = await db.fetch_user(sid)
    assert user["real_email"] == new
    assert user["verified"] is True
    assert user["relink_state"] == "relinked"
    assert user["verified_at"] is not None
    # The token issued for the OLD address must not survive: clicking that link
    # would move a now-completed user back into pending_relink.
    assert user["verification_token"] is None
    assert user["verification_expires"] is None


async def test_manual_completes_a_user_already_sitting_in_pending_relink():
    """The primary use case, and the one the PRD describes in words: the user
    clicked their link, an operator relinked their five app accounts by hand,
    and this records it. The address does not change -- only the state does."""
    sid, email = new_sid(), new_email("held")
    raw = "tok-held"
    await seed_pending(sid, email, raw)
    assert await db.mark_pending_relink(sha256_hex(raw), None, None) == sid
    assert (await db.fetch_user(sid))["relink_state"] == "pending_relink"

    message = await _override(sid, email, runner="manual", relink_done=True)
    assert "verified" in message

    user = await db.fetch_user(sid)
    assert user["real_email"] == email
    assert user["verified"] is True
    assert user["relink_state"] == "relinked"
    assert [r["action"] for r in await _audit_rows(sid)] == [
        "verify_email", "ops_override"
    ]


async def test_the_audit_row_records_the_operator_and_that_it_was_asserted():
    sid = new_sid()
    email = new_email("audited")
    await seed_pending(sid, new_email("audited-old"), "tok-audited")

    await _override(
        sid, email, runner="manual", relink_done=True,
        reason="FOSS-13: user's mail server rejects us", operator="usama@bastion",
    )

    rows = await _audit_rows(sid)
    assert [r["action"] for r in rows] == ["ops_override"]
    row = rows[0]
    assert row["email"] == email
    assert "usama@bastion" in row["user_agent"]
    assert "FOSS-13: user's mail server rejects us" in row["user_agent"]
    # The whole point of recording it: this address was taken on the operator's
    # word, and the record has to say so or a later reader cannot tell it apart
    # from a relink the platform actually checked.
    assert "asserted" in row["user_agent"]
    assert "NOT verified by the platform" in row["user_agent"]
    # No consent was given, so the consent artifact stays empty rather than
    # recording an operator's justification as something the user agreed to.
    assert row["consent_text_version"] is None
    assert row["consent_text_content"] is None


async def test_the_override_works_for_a_user_with_no_row_at_all():
    """The Zammad case: a user who can never get through the collection form
    still has to be rescuable."""
    sid, email = new_sid(), new_email("norow")
    assert await db.fetch_user(sid) is None

    await _override(sid, email, runner="manual", relink_done=True)

    user = await db.fetch_user(sid)
    assert user["real_email"] == email
    assert user["verified"] is True
    assert user["relink_state"] == "relinked"


# ---------------------------------------------------------------------------
# Case 3 of 3 — runner: enqueue, do not complete
# ---------------------------------------------------------------------------


async def test_runner_enqueues_rather_than_completing():
    sid = new_sid()
    email = new_email("queued")
    await seed_pending(sid, new_email("queued-old"), "tok-queued")

    message = await _override(sid, email, runner="runner")
    assert "queued" in message

    user = await db.fetch_user(sid)
    assert user["real_email"] == email
    # The load-bearing assertion of this whole PR: the overlay reads
    # `WHERE verified`, so an enqueue that set it would hand five apps an
    # address they have not been relinked to.
    assert user["verified"] is False
    assert user["relink_state"] == "pending_relink"
    # ops_override_write clears the token itself. Asserting it here rather than
    # only in the manual-mode test is what isolates it: manual mode also calls
    # mark_relinked, which clears the same two columns, so either clear alone
    # satisfies that test. A surviving token is not cosmetic -- clicked after
    # the override it drives mark_pending_relink, producing (TRUE,
    # 'pending_relink'), which the gate holds and part 2's runner (which selects
    # verified = FALSE) will never pick up.
    assert user["verification_token"] is None
    assert user["verification_expires"] is None
    assert [r["action"] for r in await _audit_rows(sid)] == ["ops_override"]


async def test_runner_enqueues_a_user_who_has_no_row_yet_without_verifying_them():
    """The INSERT branch, not the ON CONFLICT one.

    Written after a mutation check found the gap: flipping the inserted
    `verified` to TRUE left every enqueue test green, because they all seed a
    row first and take the UPDATE path. A verified row in pending_relink is the
    worst combination this code can produce -- the overlay serves the real
    address (it reads `WHERE verified`) while the relink is still queued, so the
    apps create the duplicate the queue exists to avoid.
    """
    sid, email = new_sid(), new_email("queue-norow")
    assert await db.fetch_user(sid) is None

    await _override(sid, email, runner="runner")

    user = await db.fetch_user(sid)
    assert user["real_email"] == email
    assert user["verified"] is False
    assert user["relink_state"] == "pending_relink"


async def test_runner_refuses_relink_done_as_contradictory():
    sid = new_sid()
    await seed_pending(sid, new_email("contra"), "tok-contra")

    with pytest.raises(OverrideRefused) as exc:
        await _override(sid, new_email("contra-new"), runner="runner", relink_done=True)
    assert "contradicts" in str(exc.value)
    assert await _audit_rows(sid) == []


async def test_runner_refuses_to_requeue_a_user_whose_address_is_already_live():
    """A relink-complete user's address is live in every app. Queueing a
    different one would leave the apps keyed to an address nobody relinked them
    to -- and clearing `verified` to avoid that is the unconditional downgrade
    submit_email's ON CONFLICT guard exists to prevent."""
    sid, live = new_sid(), new_email("live")
    await seed_relinked(sid, live)

    with pytest.raises(OverrideRefused) as exc:
        await _override(sid, new_email("live-new"), runner="runner")
    assert "live in every app" in str(exc.value)

    user = await db.fetch_user(sid)
    assert user["real_email"] == live
    assert user["verified"] is True
    # seed_relinked goes through the real endpoints, so this sid already carries
    # a verify_email row -- the assertion is that the refusal added nothing.
    assert "ops_override" not in [r["action"] for r in await _audit_rows(sid)]


# ---------------------------------------------------------------------------
# Arguments and collisions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("reason", ["", "   ", "\n"])
async def test_refuses_without_a_reason(reason):
    sid = new_sid()
    with pytest.raises(OverrideRefused) as exc:
        await run_override(
            synthetic_id=sid, email=new_email("noreason"), reason=reason,
            operator="op", runner="manual", relink_done=True,
        )
    assert "--reason is required" in str(exc.value)
    assert await db.fetch_user(sid) is None


async def test_refuses_an_invalid_email():
    sid = new_sid()
    with pytest.raises(OverrideRefused) as exc:
        await _override(sid, "not-an-address", runner="manual", relink_done=True)
    assert "not a valid email address" in str(exc.value)
    assert await db.fetch_user(sid) is None


async def test_refuses_an_address_another_account_has_verified_and_names_it():
    owner, addr = new_sid(), new_email("squatted")
    await seed_relinked(owner, addr)

    victim = new_sid()
    await seed_pending(victim, new_email("victim"), "tok-victim")

    with pytest.raises(OverrideRefused) as exc:
        await _override(victim, addr, runner="manual", relink_done=True)

    message = str(exc.value)
    assert owner in message, "the conflicting synthetic_id must be named"
    assert addr in message

    # Nothing written for the victim, and the owner is untouched.
    assert (await db.fetch_user(victim))["real_email"] != addr
    assert await _audit_rows(victim) == []
    assert (await db.fetch_user(owner))["verified"] is True


async def test_the_collision_check_is_case_insensitive_like_the_index():
    """idx_foss_users_email is UNIQUE (lower(real_email)) WHERE verified, so a
    case-sensitive probe here would refuse to refuse -- and mark_relinked would
    then blow up on the index instead of producing the message that names the
    other account."""
    owner, addr = new_sid(), new_email("mixedcase")
    await seed_relinked(owner, addr)

    victim = new_sid()
    with pytest.raises(OverrideRefused) as exc:
        await _override(victim, addr.upper(), runner="manual", relink_done=True)
    assert owner in str(exc.value)


async def test_reclaiming_your_own_verified_address_is_not_a_collision():
    """The refusal is about a DIFFERENT account holding the address."""
    sid, addr = new_sid(), new_email("mine")
    await seed_relinked(sid, addr)

    message = await _override(sid, addr, runner="manual", relink_done=True)
    assert "Nothing to do" in message


# ---------------------------------------------------------------------------
# Idempotence and the cache
# ---------------------------------------------------------------------------


async def test_running_it_twice_does_not_error_or_double_audit():
    sid, email = new_sid(), new_email("twice")
    await seed_pending(sid, new_email("twice-old"), "tok-twice")

    await _override(sid, email, runner="manual", relink_done=True)
    second = await _override(sid, email, runner="manual", relink_done=True)

    assert "Nothing to do" in second
    assert [r["action"] for r in await _audit_rows(sid)] == ["ops_override"], (
        "a re-run must not record a change that did not happen"
    )
    user = await db.fetch_user(sid)
    assert user["verified"] is True
    assert user["relink_state"] == "relinked"


async def test_enqueueing_twice_does_not_double_audit():
    sid, email = new_sid(), new_email("twicequeue")
    await seed_pending(sid, new_email("twicequeue-old"), "tok-twicequeue")

    await _override(sid, email, runner="runner")
    second = await _override(sid, email, runner="runner")

    assert "Nothing to do" in second
    assert [r["action"] for r in await _audit_rows(sid)] == ["ops_override"]
    assert (await db.fetch_user(sid))["relink_state"] == "pending_relink"


async def test_the_override_evicts_the_gate_memo():
    """Without this the user the operator just rescued keeps being bounced for
    up to the cache TTL, at a page that renders nothing to explain why.

    In-process only, and that is the honest scope of this test: the CLI runs in
    its own `docker compose exec` process, so in a real deployment it evicts its
    own empty cache and the serving container's memo expires on the TTL instead
    -- the same bounded gap db.mark_relinked documents for part 2's runner.
    """
    sid, email = new_sid(), new_email("memo")
    await seed_pending(sid, email, "tok-memo")

    gate._clear_cache()
    verified, cached_email, state = await gate.verified_state(sid, ttl_seconds=300)
    assert (verified, state) == (False, "none")
    assert cached_email == email

    new = new_email("memo-new")
    await _override(sid, new, runner="manual", relink_done=True)

    # Re-read within the TTL: a live memo would still say unverified.
    verified, cached_email, state = await gate.verified_state(sid, ttl_seconds=300)
    assert verified is True
    assert cached_email == new
    assert state == "relinked"


async def test_an_enqueue_alone_evicts_the_gate_memo():
    """Runner mode never reaches mark_relinked, so ops_override_write's own
    eviction is the only one that can fire.

    The sibling test above drives manual + --relink-done, which evicts twice;
    either eviction alone satisfies it, so neither site is individually covered
    there. Without this the operator sees the enqueue succeed while the gate
    keeps serving the pre-override address for the rest of the TTL.
    """
    sid, email = new_sid(), new_email("memo-enqueue")
    await seed_pending(sid, email, "tok-memo-enqueue")

    gate._clear_cache()
    assert await gate.verified_state(sid, ttl_seconds=300) == (False, email, "none")

    new = new_email("memo-enqueue-new")
    await _override(sid, new, runner="runner")

    verified, cached_email, state = await gate.verified_state(sid, ttl_seconds=300)
    assert verified is False
    assert cached_email == new
    assert state == "pending_relink"


async def test_mark_relinked_alone_evicts_the_gate_memo():
    """mark_relinked is what part 2's runner calls standalone, in a process
    that never touches ops_override_write, and it is where round 2's fix moved
    the eviction to after the transaction commits. A regression here holds a
    just-completed user at RELINKING for the full TTL."""
    sid, email = new_sid(), new_email("memo-relinked")
    await seed_pending(sid, email, "tok-memo-relinked")
    assert (
        await db.mark_pending_relink(sha256_hex("tok-memo-relinked"), None, None) == sid
    )

    gate._clear_cache()
    assert await gate.verified_state(sid, ttl_seconds=300) == (
        False,
        email,
        "pending_relink",
    )

    assert await db.mark_relinked(sid) is True

    verified, cached_email, state = await gate.verified_state(sid, ttl_seconds=300)
    assert verified is True
    assert state == "relinked"


# ---------------------------------------------------------------------------
# Argument plumbing
# ---------------------------------------------------------------------------


def test_the_cli_requires_reason_email_and_synthetic_id():
    """argparse, not the function: the flags are the operator-facing contract
    and platform.sh passes them positionally by name."""
    from src.ops_override import _parse_args

    for argv in (
        ["--email", "a@b.com", "--reason", "r"],
        ["--synthetic-id", "u", "--reason", "r"],
        ["--synthetic-id", "u", "--email", "a@b.com"],
    ):
        with pytest.raises(SystemExit):
            _parse_args(argv)

    args = _parse_args(
        ["--synthetic-id", "u", "--email", "a@b.com", "--reason", "r", "--relink-done"]
    )
    assert args.relink_done is True
    # Defaults to off: the assertion has to be made, never inherited.
    assert _parse_args(
        ["--synthetic-id", "u", "--email", "a@b.com", "--reason", "r"]
    ).relink_done is False


async def test_runner_refuses_a_verified_user_stuck_mid_relink():
    """The refusal must key off `verified`, not is_relink_complete.

    ops_override_write and mark_relinked are separate transactions, so a
    `manual` run interrupted between them leaves (verified=TRUE,
    relink_state='pending_relink') durably. is_relink_complete calls that
    incomplete -- correct for the gate, which should hold them -- but the
    overlay reads WHERE verified, so the address is LIVE. Keying the refusal
    off completeness let an enqueue through onto a live address, and part 2's
    runner would then relink app accounts onto an address they were never
    keyed to.
    """
    sid, live = new_sid(), new_email("live")
    await seed_pending(sid, live, "tok-stuck")
    await db.ops_override_write(sid, live, audit_note="probe")
    await db.mark_relinked(sid)
    # Force the interrupted-manual state: verified, but back in pending_relink.
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE foss_users SET relink_state = 'pending_relink' WHERE synthetic_id = $1",
            sid,
        )
    user = await db.fetch_user(sid)
    assert (user["verified"], user["relink_state"]) == (True, "pending_relink")
    assert gate.is_relink_complete(
        verified=user["verified"], relink_state=user["relink_state"]
    ) is False, "precondition: the old refusal would not have fired"

    with pytest.raises(OverrideRefused) as exc:
        await _override(sid, new_email("different"), runner="runner")
    assert "live in every app" in str(exc.value)

    unchanged = await db.fetch_user(sid)
    assert unchanged["real_email"] == live


async def test_a_losing_race_on_the_address_refuses_rather_than_tracebacks():
    """verified_owner() is an unlocked probe under READ COMMITTED, so another
    account can verify the address between it and the write. Setting real_email
    on an already-verified row makes the partial index apply to that statement;
    uncaught it surfaced a raw asyncpg traceback and exit 1, while the command's
    contract is that 2 means refused and nothing was written."""
    shared = new_email("contested")
    winner, loser = new_sid(), new_sid()

    await seed_pending(winner, shared, "tok-winner")
    await db.ops_override_write(winner, shared, audit_note="probe")
    await db.mark_relinked(winner)

    # loser is already verified on another address, so the write below targets a
    # verified row and the partial index applies to it.
    await seed_pending(loser, new_email("loser-own"), "tok-loser")
    await db.ops_override_write(loser, new_email("loser-own"), audit_note="probe")
    await db.mark_relinked(loser)

    with pytest.raises(db.EmailAlreadyRegistered):
        await db.ops_override_write(loser, shared, audit_note="probe")

    still = await db.fetch_user(loser)
    assert still["real_email"] != shared, "nothing may be written on a refusal"


async def test_a_race_lost_at_the_write_refuses_instead_of_tracebacking(monkeypatch):
    """Covers run_override's except around ops_override_write.

    Deleting that except left all 189 tests green: the existing race test calls
    db.ops_override_write directly, so it proved the database half and none of
    the CLI contract. The branch is unreachable by ordinary means because
    verified_owner() refuses first whenever another account genuinely owns the
    address -- so the race itself has to be simulated. That IS the race:
    verified_owner is an unlocked probe under READ COMMITTED, and another
    account can verify the address between it and the write.

    Manual mode, because runner mode hits the `verified` refusal first.
    """
    contested = new_email("contested-race")
    winner, target = new_sid(), new_sid()

    await seed_pending(winner, contested, "tok-race-winner")
    await db.ops_override_write(winner, contested, audit_note="probe")
    await db.mark_relinked(winner)

    own = new_email("target-own")
    await seed_pending(target, own, "tok-race-target")
    await db.ops_override_write(target, own, audit_note="probe")
    await db.mark_relinked(target)

    # The probe misses the winner -- exactly what a lost race looks like.
    async def _stale_probe(email):
        return None

    monkeypatch.setattr(db, "verified_owner", _stale_probe)

    with pytest.raises(OverrideRefused) as exc:
        await _override(target, contested, runner="manual", relink_done=True)

    assert "between this command's check and its write" in str(exc.value)

    unchanged = await db.fetch_user(target)
    assert unchanged["real_email"] == own, "a refusal must write nothing"


async def test_runner_refuses_a_stuck_user_even_for_the_same_address():
    """The queue-idempotence short-circuit must not swallow a verified row.

    The sibling test uses a DIFFERENT address, so it exercises the refusal but
    not this ordering: the short-circuit runs first and, without its
    `not user["verified"]` clause, reports "already queued / nothing to do" for
    a row that part 2's runner will never pick up (it selects pending_relink
    AND verified = FALSE). The user stays held at RELINKING forever while the
    escape hatch claims success -- and the runbook tells operators to re-run
    with the same arguments when unsure whether the first run got through, so
    this is the likely path rather than an exotic one.
    """
    sid, live = new_sid(), new_email("stuck-same")
    await seed_pending(sid, live, "tok-stuck-same")
    await db.ops_override_write(sid, live, audit_note="probe")
    await db.mark_relinked(sid)
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE foss_users SET relink_state = 'pending_relink' WHERE synthetic_id = $1",
            sid,
        )
    assert (await db.fetch_user(sid))["verified"] is True

    with pytest.raises(OverrideRefused) as exc:
        await _override(sid, live, runner="runner")

    msg = str(exc.value)
    assert "never completed" in msg
    assert "--relink-done" in msg, "must point at the path that can actually finish it"


# ---------------------------------------------------------------------------
# Round 4 — a synthetic address is an identity token, not a mailbox
#
# The operator can SEE these strings: they are on the ForwardAuth header, in
# `docker logs`, and in psql. Pasting one is the natural mistake, and nothing
# in the data checks can catch it -- a synthetic address is never stored as
# anyone's real_email, so verified_owner() finds no conflict and the write went
# straight through.
# ---------------------------------------------------------------------------


async def test_own_synthetic_address_is_refused(monkeypatch):
    """Completing a relink onto the user's OWN synthetic address is a WORSE
    lockout than the one being fixed: the overlay serves it as verified, and
    decide_gate then reads relink-complete AND email == f"{sid}@{domain}" ->
    REFRESH -> /oauth2/sign_in -> the same claim -> REFRESH, forever, on every
    gated app.
    """
    monkeypatch.setattr(settings, "synthetic_email_domain", "askii.ai")
    sid, seeded = new_sid(), new_email("selfsynth")
    await seed_pending(sid, seeded, "tok-selfsynth")

    with pytest.raises(OverrideRefused) as exc:
        await _override(sid, f"{sid}@askii.ai", runner="manual", relink_done=True)

    message = str(exc.value)
    assert "own synthetic address" in message
    assert "not a mailbox" in message
    # Must name the consequence, not merely refuse: an operator told only
    # "invalid" retries with a variation of the same string.
    assert "forever" in message or "sign_in" in message

    # Nothing written: the row is exactly as seeded. Asserted against the
    # SEEDED values rather than against a state seed_pending never produces --
    # it inserts directly, so relink_state is its 'none' default and no audit
    # row exists. `verified is False` is the load-bearing one: under 'runner'
    # the command refuses to touch an already-verified row, so a write here
    # would be a lockout the override itself cannot undo.
    user = await db.fetch_user(sid)
    assert user["verified"] is False
    assert user["real_email"] == seeded, "the synthetic address must not have been stored"
    assert user["relink_state"] == "none"
    assert "ops_override" not in [r["action"] for r in await _audit_rows(sid)]


async def test_another_accounts_synthetic_address_is_refused(monkeypatch):
    """The cross-sid variant is account takeover, not just a lockout: the
    address resolves to ALLOW (it is not THIS sid's synthetic string), and all
    five apps key identity on the email string alone.
    """
    monkeypatch.setattr(settings, "synthetic_email_domain", "askii.ai")
    victim, attacker = new_sid(), new_sid()
    attacker_seeded = new_email("attacker")
    await seed_pending(victim, new_email("victim"), "tok-victim")
    await seed_pending(attacker, attacker_seeded, "tok-attacker")

    with pytest.raises(OverrideRefused) as exc:
        await _override(
            attacker, f"{victim}@askii.ai", runner="manual", relink_done=True
        )

    message = str(exc.value)
    assert "another account's synthetic address" in message
    assert victim in message, "name the account, so the operator can tell what they hit"

    # Nothing written. seed_pending inserts directly, so there is no audit row
    # to compare against -- the assertion that carries weight is that the
    # victim's synthetic address was not stored as the attacker's real_email,
    # which is the takeover itself.
    user = await db.fetch_user(attacker)
    assert user["verified"] is False
    assert user["real_email"] == attacker_seeded
    assert "ops_override" not in [r["action"] for r in await _audit_rows(attacker)]


async def test_a_real_mailbox_at_the_synthetic_domain_is_still_accepted(monkeypatch):
    """The refusal is an exact full-string match, NOT an `@domain` suffix test.

    The synthetic domain is also a real Moneta mail domain -- decide_gate
    matches the whole string for exactly this reason -- so a suffix refusal
    would reject legitimate mailboxes and lock out the people it is meant to
    rescue.
    """
    monkeypatch.setattr(settings, "synthetic_email_domain", "askii.ai")
    sid = new_sid()
    await seed_pending(sid, new_email("realatdomain"), "tok-realatdomain")

    # A real human mailbox that happens to live at the synthetic domain, whose
    # local part is not any account's synthetic_id.
    result = await _override(
        sid, "jane.doe@askii.ai", runner="manual", relink_done=True
    )

    assert "jane.doe@askii.ai" in result
    user = await db.fetch_user(sid)
    assert user["verified"] is True
    assert user["real_email"] == "jane.doe@askii.ai"


async def test_the_synthetic_refusal_is_skipped_when_the_domain_is_unset(monkeypatch):
    """With SYNTHETIC_EMAIL_DOMAIN empty there is no synthetic string to
    recognise, and f"{sid}@" would match nothing anyway. Fail open to the checks
    below rather than refusing everything -- /api/authz already refuses to gate
    at all in that configuration, so the override is the only way back.
    """
    monkeypatch.setattr(settings, "synthetic_email_domain", "")
    sid = new_sid()
    await seed_pending(sid, new_email("nodomain"), "tok-nodomain")

    result = await _override(
        sid, new_email("nodomain-new"), runner="manual", relink_done=True
    )
    assert (await db.fetch_user(sid))["verified"] is True
    assert "relink" in result.lower() or "complete" in result.lower()


async def test_a_missing_audit_vocabulary_is_refused_not_a_traceback(
    monkeypatch, admin_conn
):
    """'ops_override' is an accepted audit action only after the audit CHECK is
    widened -- a SEPARATE runbook step from the relink_state migration, so an
    upgrader can apply one and not the other.

    Uncaught, the CheckViolationError escaped run_override as a raw Postgres
    traceback with exit 1, while the command's documented contract is that 2
    means refused. Nothing is lost either way (the row and audit writes share a
    transaction), but an operator mid-incident cannot tell that the schema is
    the problem.

    Uses admin_conn, NOT db.get_pool(). foss_users_audit is owned by `postgres`
    (init-databases.sh runs as $POSTGRES_USER) and launchpad_api_user holds only
    SELECT, INSERT -- ALTER TABLE needs ownership. Over the application pool
    this raises InsufficientPrivilegeError in setup and the assertions below
    never run, which is the failure mode conftest's admin_conn fixture exists
    for.

    Both ALTERs live inside the try: a failure between the DROP and the ADD
    would otherwise leave the table with no CHECK at all for the rest of the
    session, and every later test relying on the vocabulary being enforced
    would pass vacuously.
    """
    monkeypatch.setattr(settings, "synthetic_email_domain", "askii.ai")
    sid, email = new_sid(), new_email("noaudit")
    await seed_pending(sid, email, "tok-noaudit")

    _FULL = (
        "'submit_email','verify_email','resend_verification','dismiss_modal',"
        "'submit_email_collision','rate_limited','ops_override'"
    )
    _NARROWED = (
        "'submit_email','verify_email','resend_verification','dismiss_modal',"
        "'submit_email_collision','rate_limited'"
    )

    try:
        await admin_conn.execute(
            "ALTER TABLE foss_users_audit "
            "DROP CONSTRAINT IF EXISTS foss_users_audit_action_check"
        )
        await admin_conn.execute(
            "ALTER TABLE foss_users_audit ADD CONSTRAINT "
            f"foss_users_audit_action_check CHECK (action IN ({_NARROWED}))"
        )

        with pytest.raises(OverrideRefused) as exc:
            await _override(
                sid, new_email("noaudit-new"), runner="manual", relink_done=True
            )

        message = str(exc.value)
        assert "'ops_override'" in message
        assert "runbook" in message.lower(), (
            "an operator needs the fix, not just the fault"
        )

        # The transaction rolled back cleanly: no half-applied override.
        user = await db.fetch_user(sid)
        assert user["verified"] is False
        assert user["real_email"] == email
        assert "ops_override" not in [r["action"] for r in await _audit_rows(sid)]
    finally:
        await admin_conn.execute(
            "ALTER TABLE foss_users_audit "
            "DROP CONSTRAINT IF EXISTS foss_users_audit_action_check"
        )
        await admin_conn.execute(
            "ALTER TABLE foss_users_audit ADD CONSTRAINT "
            f"foss_users_audit_action_check CHECK (action IN ({_FULL}))"
        )


async def test_a_mixed_case_synthetic_address_is_still_refused(monkeypatch):
    """Round 5 regression. The caller derives the local part from
    `email.lower()`, so an exact-match probe against synthetic_id never fires
    for any sid carrying an uppercase character -- and pasting the sid verbatim
    out of the logs is exactly the input the guard exists to catch.

    Reverting synthetic_id_exists to `WHERE synthetic_id = $1` fails this.
    """
    monkeypatch.setattr(settings, "synthetic_email_domain", "askii.ai")
    victim, attacker = f"test_MiXeD{new_sid()[5:]}", new_sid()
    await seed_pending(victim, new_email("mixedvictim"), "tok-mixedvictim")
    await seed_pending(attacker, new_email("mixedattacker"), "tok-mixedattacker")
    assert any(c.isupper() for c in victim), "the sid must carry case to mean anything"

    with pytest.raises(OverrideRefused) as exc:
        await _override(
            attacker, f"{victim}@askii.ai", runner="manual", relink_done=True
        )
    assert "another account's synthetic address" in str(exc.value)

    user = await db.fetch_user(attacker)
    assert user["verified"] is False
    assert "ops_override" not in [r["action"] for r in await _audit_rows(attacker)]
