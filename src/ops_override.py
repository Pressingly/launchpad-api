"""Operator unblock: set a user's email and complete (or enqueue) their relink.

**Read the refusals before the happy path.** Everything interesting in this
module is a refusal, and each one exists because the alternative silently
destroys a user's content.

Once the verify-gate is enforced, app access depends on email deliverability. A
user whose mail bounces, lands in spam, or whose inbox is simply unreachable is
locked out of *every* app -- not degraded, locked out. On Zammad it is worse: an
address collision makes the shim return 403 and local login is disabled, so
there is no recovery path at all. This is the escape hatch for that.

**A CLI, not an endpoint.** The stack has no RBAC, so "operator only" cannot be
enforced in-app today; an HTTP endpoint would be reachable from every app
container on the `backend` network. A command run inside the launchpad-api
container, invoked from the host by `platform.sh --launchpad-override`,
inherits the trust boundary the provisioning scripts already use.

Why the whole thing branches on LAUNCHPAD_RELINK_RUNNER
-------------------------------------------------------
Pre-runner, marking a user `relinked` makes the mpass overlay start returning
their real email while their app accounts still hold synthetic addresses -- so
every app creates a *second* account and their existing content is stranded.
That is precisely the bug the gate exists to prevent, and an operator reaching
for this command to rescue a locked-out user would be destroying their work
instead. A code comment does not cover that, so the behaviour is:

    (empty)   refuse -- no mechanism exists to relink anything
    manual    require --relink-done; the operator asserts they relinked by hand
    runner    enqueue (relink_state = 'pending_relink'); the runner completes it
    anything else   refuse -- exact, case-sensitive match, same as platform.sh

The same three values gate `platform.sh --up` (`_validate_launchpad_switch`).
Both sides match exactly and case-sensitively; if you change one, change the
other and the runbook table with it.

Re-queueing a `relink_failed` user
-----------------------------------
Under `runner` mode, a relink script exiting 2 (a collision only a human can
resolve) sets `relink_state = 'relink_failed'`; the runner will not retry it.
There is no separate flag for putting that user back in the queue: once an
operator has resolved the collision by hand, the ordinary `runner`-mode
invocation of this command (no `--relink-done`) re-queues them, because
`db.ops_override_write` sets `relink_state = 'pending_relink'`
unconditionally, regardless of what state the row was already in. See the
comment above the idempotence check in `run_override` for why this does not
collide with the "already queued" no-op.

`--relink-done` is unverified, deliberately
-------------------------------------------
Nothing here checks that the five app accounts were actually relinked; the
operator asserts it. Verifying it would mean this command reaching into five
application databases -- the runner's job, and the privilege expansion the CLI
form exists to avoid. It is also the one place where a wrong assertion silently
produces the duplicate, so the assertion is printed in full before it is acted
on, and the audit row records that the override was taken on the operator's
word rather than on anything the platform checked.
"""
import argparse
import asyncio
import os
import sys
from typing import Optional

from pydantic import BaseModel, EmailStr, ValidationError

from src import db
from src.config import settings
from src.gate import is_relink_complete

# The two values that mean a relink can happen. Exact, case-sensitive; see the
# module docstring and platform.sh's _validate_launchpad_switch.
RUNNER_MANUAL = "manual"
RUNNER_RUNNER = "runner"
VALID_RUNNERS = (RUNNER_MANUAL, RUNNER_RUNNER)

# Printed before a `manual` override is applied, and again (as the reason for
# refusing) when --relink-done is missing. One string, so the operator cannot be
# shown a weaker version of the assertion than the one they are making.
ASSERTION = """\
--relink-done asserts ALL of the following. Nothing here verifies any of it:

  * You have already moved this user's existing accounts in every app
    (Outline, Penpot, Plane, Twenty, Zammad) onto the address you passed as
    --email, by hand.
  * You did that BEFORE running this command.

If that is not true, this command does not rescue the user: completing the
relink makes the mpass overlay start serving their real address while their app
accounts still hold the synthetic one, so the next time they open each app it
creates a SECOND account and their existing content is stranded behind the old
one. That is the exact failure the verify-gate exists to prevent."""


class OverrideRefused(Exception):
    """The override will not be applied. The message is the operator's answer.

    A distinct exception rather than a return code because every caller must
    treat these as terminal: there is no partial application to report and
    nothing has been written.
    """


class _EmailArg(BaseModel):
    """Validate --email the same way the API validates a submission.

    Not decoration: `real_email` feeds the mpass overlay, which is what every
    app reads identity from. An operator typo that produced a syntactically
    invalid address would be handed to five applications as a principal.
    """

    email: EmailStr


def _normalise_email(raw: str) -> str:
    try:
        return str(_EmailArg(email=raw).email)
    except ValidationError:
        raise OverrideRefused(
            f"--email {raw!r} is not a valid email address. The value becomes "
            "this user's identity in every app, so it is not accepted "
            "unvalidated."
        )


def _resolve_runner(runner: Optional[str]) -> str:
    """The deployed relink mechanism, from the environment unless overridden.

    `runner=None` means "read the environment", which is what the CLI does.
    Tests pass the value explicitly for the three-case matrix, and one test
    asserts the environment binding itself -- a field name that failed to bind
    would read empty and refuse everything, which is indistinguishable from the
    override refusing correctly.
    """
    return settings.launchpad_relink_runner if runner is None else runner.strip()


def _audit_note(operator: str, mode: str, reason: str) -> str:
    """The audit row's record of who did this and on what authority.

    Goes in `user_agent`. The consent columns are left NULL because no consent
    was given -- see db.ops_override_write for why writing an operator's
    justification into the consent artifact is not an option.
    """
    if mode == RUNNER_MANUAL:
        authority = (
            "relink asserted by operator via --relink-done, NOT verified by the "
            "platform"
        )
    else:
        authority = "relink enqueued for the runner (relink_state=pending_relink)"
    return (
        f"platform.sh --launchpad-override; operator={operator}; "
        f"{authority}; reason: {reason}"
    )


async def run_override(
    *,
    synthetic_id: str,
    email: str,
    reason: str,
    operator: str,
    relink_done: bool = False,
    runner: Optional[str] = None,
) -> str:
    """Apply the override. Returns the line to print; raises OverrideRefused.

    The order of the checks is load-bearing: everything that can refuse runs
    before anything is written, and the idempotent no-op is detected before the
    audit write so a second run produces exactly one `ops_override` row rather
    than a second one recording a change that did not happen.
    """
    synthetic_id = synthetic_id.strip()
    if not synthetic_id:
        raise OverrideRefused("A synthetic_id is required.")

    # The audit row is the entire point of this command being an override rather
    # than a database edit, and a row with no reason records nothing.
    reason = reason.strip()
    if not reason:
        raise OverrideRefused(
            "--reason is required and must not be empty. The audit row is the "
            "point of this command: it is the only record that this address did "
            "not come from the user."
        )

    email = _normalise_email(email)
    mode = _resolve_runner(runner)

    # -- Refusals that depend on the deployed mechanism ----------------------
    if not mode:
        raise OverrideRefused(
            "LAUNCHPAD_RELINK_RUNNER is empty, so no relink mechanism is "
            "deployed and this override will not complete anything.\n\n"
            "Completing a relink that has not happened does not rescue this "
            "user: the mpass overlay would start serving their real address "
            "while their accounts in every app still hold the synthetic one, so "
            "each app would create a SECOND, empty account and strand the "
            "content they already have.\n\n"
            "If you have relinked their app accounts by hand, set "
            "LAUNCHPAD_RELINK_RUNNER=manual in .env and re-run with "
            "--relink-done. Set 'runner' only once the automated relink runner "
            "actually exists. See dev/docs/launchpad-runbook.md."
        )

    if mode not in VALID_RUNNERS:
        raise OverrideRefused(
            f"LAUNCHPAD_RELINK_RUNNER is set to {mode!r}, which is not a value "
            "this platform understands. It must be exactly 'manual' or "
            "'runner' -- the match is case-sensitive -- or empty for neither. "
            "Fix it in .env. See dev/docs/launchpad-runbook.md."
        )

    if mode == RUNNER_MANUAL and not relink_done:
        raise OverrideRefused(
            "LAUNCHPAD_RELINK_RUNNER=manual, so this override completes the "
            "user's relink and requires --relink-done.\n\n"
            f"{ASSERTION}\n\n"
            "Do the per-app relink first, then re-run with --relink-done."
        )

    if mode == RUNNER_RUNNER and relink_done:
        raise OverrideRefused(
            "--relink-done contradicts LAUNCHPAD_RELINK_RUNNER=runner. Under "
            "'runner' this command does not complete anything: it enqueues the "
            "relink (relink_state = 'pending_relink') and the runner finishes "
            "it. Re-run without --relink-done, or set "
            "LAUNCHPAD_RELINK_RUNNER=manual if you are doing the relinks by "
            "hand."
        )

    # A synthetic address is an identity token, never a mailbox. Refused here
    # rather than left to the data checks below, because no data check can see
    # it: synthetic addresses are never stored as anyone's real_email, so
    # verified_owner() finds nothing and the write goes straight through.
    #
    # Deliberately an exact full-string match, not an `@{domain}` suffix test.
    # The synthetic domain is also a real Moneta mail domain (see decide_gate's
    # docstring), so refusing the suffix outright would reject legitimate
    # mailboxes.
    #
    # Two distinct failures, both reachable from an address the operator can
    # see in `docker logs`, in psql, or on the ForwardAuth header:
    #
    #   self  -- completing a relink onto the user's OWN synthetic address makes
    #            the overlay serve it as verified. decide_gate then reads
    #            relink-complete AND email == f"{sid}@{domain}" -> REFRESH, which
    #            302s to /oauth2/sign_in, re-mints the same claim and returns
    #            REFRESH again: an infinite redirect on every gated app. That is
    #            a harder lockout than the one the override was reached for, and
    #            under 'runner' this command then refuses to repair it because
    #            the user is already verified.
    #
    #   cross -- another account's synthetic address resolves to ALLOW, and all
    #            five apps key identity on the email string, so this sid is
    #            handed that account's data.
    synthetic_domain = settings.synthetic_email_domain
    if synthetic_domain:
        if email.lower() == f"{synthetic_id}@{synthetic_domain}".lower():
            raise OverrideRefused(
                f"{email} is {synthetic_id}'s own synthetic address, not a "
                "mailbox. Completing a relink onto it makes the overlay serve "
                "the synthetic address as if it were verified, and the gate "
                "then bounces the user through /oauth2/sign_in forever -- a "
                "worse lockout than the one you are fixing. Use the real "
                "address the user gave you."
            )
        local_part, _, domain = email.lower().partition("@")
        if domain == synthetic_domain.lower() and await db.synthetic_id_exists(
            local_part
        ):
            raise OverrideRefused(
                f"{email} is another account's synthetic address (synthetic_id "
                f"{local_part}), not a mailbox. Every app keys identity on the "
                f"email string, so this would hand {synthetic_id} that "
                "account's data. Use the real address the user gave you."
            )

    # -- Refusals that depend on the data -----------------------------------
    # Address squatting, and only that: the address is already VERIFIED by a
    # different account. Surface it with the conflicting sid rather than letting
    # idx_foss_users_email fire -- which of two accounts keeps an address is a
    # human decision, and an operator told only "taken" cannot make it.
    owner = await db.verified_owner(email)
    if owner is not None and owner != synthetic_id:
        raise OverrideRefused(
            f"{email} is already verified by a different account: "
            f"synthetic_id {owner}. Refusing rather than colliding -- which "
            "account keeps this address is a decision for a human. Resolve it "
            f"first (either use a different address for {synthetic_id}, or "
            f"clear it from {owner}), then re-run."
        )

    user = await db.fetch_user(synthetic_id)
    same_address = user is not None and user["real_email"].lower() == email.lower()
    complete_already = user is not None and is_relink_complete(
        verified=user["verified"], relink_state=user["relink_state"]
    )

    # -- Idempotence: detected BEFORE the audit write ------------------------
    # Re-running must not error and must not write a second ops_override row
    # recording a change that did not happen. An operator who cannot tell
    # whether the first run got through has to be able to just run it again.
    if same_address and complete_already:
        return (
            f"{synthetic_id} already holds {email} with the relink complete. "
            "Nothing to do; no audit row written."
        )
    # `not user["verified"]` is load-bearing. Without it this short-circuit
    # fires BEFORE the refusal below and reports success for the one state that
    # most needs refusing: (verified=TRUE, pending_relink), left by an
    # interrupted manual run, with the address already live in the overlay.
    # Part 2's runner selects pending_relink AND verified = FALSE, so it will
    # never pick that row up -- the user stays held at RELINKING forever while
    # the escape hatch said "Nothing to do". The runbook tells operators to
    # re-run when unsure, so this is the likely path, not an exotic one.
    if (
        mode == RUNNER_RUNNER
        and same_address
        and user["relink_state"] == "pending_relink"
        and not user["verified"]
    ):
        return (
            f"{synthetic_id} is already queued for relink onto {email}. "
            "Nothing to do; no audit row written."
        )

    # `relink_state == "pending_relink"` above is an exact match, deliberately
    # not "already enqueued in some sense": a `relink_failed` row (the runner
    # hit a collision only a human can resolve) does NOT match it, so it never
    # takes this no-op branch. That is what makes re-queueing work below --
    # there is no new flag for it. Once the operator has resolved the
    # collision by hand (freeing the address `verified_owner` checks above),
    # a plain runner-mode re-run of this same command falls through to the
    # ordinary write further down, and `db.ops_override_write` sets
    # relink_state = 'pending_relink' unconditionally regardless of the row's
    # current state -- so re-running this command IS how an operator re-queues
    # a relink_failed user. If a future change adds a guard keyed on
    # relink_state here, it must not treat 'relink_failed' as "already
    # handled", or re-queueing silently stops working.

    # A relink-complete user's address is LIVE -- the overlay is serving it and
    # the apps are keyed to it. Enqueueing would leave that true while the
    # runner moves the accounts, so between the two the apps hold an address
    # they were never relinked to. Do not clear `verified` to fix that either:
    # an unconditional downgrade is what makes every app see a different
    # principal, which is why submit_email's ON CONFLICT is restricted to
    # unverified rows. Changing a live address needs the app accounts moved
    # first, which is exactly what the manual path asserts.
    #
    # Test `verified` itself, NOT is_relink_complete. A row can be
    # (verified=TRUE, relink_state='pending_relink') -- ops_override_write and
    # mark_relinked are separate transactions, so a `manual` run interrupted
    # between them lands there durably, and its own EmailAlreadyRegistered
    # branch below says so in as many words. is_relink_complete calls that
    # state incomplete, which is right for the gate (hold them) but wrong here:
    # the overlay reads `WHERE verified`, so the address is live regardless of
    # relink_state, and keying the refusal off completeness let an enqueue
    # through onto a live address.
    if mode == RUNNER_RUNNER and user is not None and user["verified"]:
        if same_address:
            # An interrupted manual run: the address is already live but the
            # relink never completed. Saying "queueing a different one" here
            # would describe a situation the operator is not in.
            raise OverrideRefused(
                f"{synthetic_id} is verified on {email} but the relink was "
                "never completed -- most likely a manual run interrupted "
                "between setting the address and completing it. The address is "
                "already live in every app, and the runner only picks up rows "
                "that are not yet verified, so queueing would leave them held "
                "forever. Finish it by hand instead: set "
                "LAUNCHPAD_RELINK_RUNNER=manual and re-run with --relink-done."
            )
        raise OverrideRefused(
            f"{synthetic_id} already has a completed relink on "
            f"{user['real_email']}, so that address is live in every app. "
            "Queueing a different one would leave the apps keyed to an address "
            "nobody relinked them to. Relink their app accounts onto "
            f"{email} by hand, set LAUNCHPAD_RELINK_RUNNER=manual, and re-run "
            "with --relink-done."
        )

    note = _audit_note(operator, mode, reason)
    try:
        await db.ops_override_write(synthetic_id, email, audit_note=note)
    except db.EmailAlreadyRegistered:
        # verified_owner() above is an unlocked probe, so another account can
        # verify this address between that check and this write. Refuse with
        # exit 2 like every other refusal rather than surfacing a traceback:
        # nothing was written, because the row and the audit share one
        # transaction.
        raise OverrideRefused(
            f"{email} was verified by another account between this command's "
            "check and its write. Nothing was written. Resolve the conflict "
            "and re-run."
        )
    except db.AuditVocabularyMissing:
        # A schema gap, not a conflict. Refuse with exit 2 and name the fix:
        # untranslated this reached the operator as a raw Postgres traceback
        # with exit 1, giving no hint that a migration step was skipped.
        raise OverrideRefused(
            "This database's foss_users_audit CHECK does not accept the "
            "'ops_override' action yet, so the override cannot be audited and "
            "nothing was written.\n\n"
            "The audit-vocabulary widening is a separate step from the "
            "relink_state migration -- applying one does not apply the other. "
            "Run the audit-vocabulary block in dev/docs/launchpad-runbook.md "
            "against the launchpad database, then re-run."
        )

    if mode == RUNNER_RUNNER:
        return (
            f"{synthetic_id} is now queued for relink onto {email} "
            "(relink_state = 'pending_relink'). The runner will complete them; "
            "the gate holds them until it does."
        )

    # mark_relinked is the only thing in the codebase that sets `verified`, and
    # it is what makes the address live. It cannot report "no such row" here --
    # ops_override_write has just written one -- but a concurrent verification
    # of the same address elsewhere can still lose the race to the partial
    # index, which is what the catch below is for.
    try:
        completed = await db.mark_relinked(synthetic_id)
    except db.EmailAlreadyRegistered:
        raise OverrideRefused(
            f"{email} was verified by another account between this command's "
            "check and its write. The address was set but the relink was NOT "
            "completed, and an ops_override audit row records the attempt. "
            "Resolve the conflict and re-run."
        )
    if not completed:
        raise OverrideRefused(
            f"No foss_users row for {synthetic_id} after writing one -- it was "
            "deleted concurrently. Nothing was completed; re-run."
        )

    return (
        f"{synthetic_id} is now verified on {email} with the relink recorded as "
        "complete, on your assertion that their app accounts were relinked by "
        "hand. The audit row records that."
    )


def _parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.ops_override",
        description=(
            "Set a user's email and complete or enqueue their relink on an "
            "operator's authority. Normally invoked as "
            "`./platform.sh --launchpad-override`."
        ),
    )
    parser.add_argument("--synthetic-id", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--reason", required=True)
    parser.add_argument(
        "--relink-done",
        action="store_true",
        help=(
            "Assert that this user's accounts in every app have ALREADY been "
            "relinked onto --email by hand. Required under "
            "LAUNCHPAD_RELINK_RUNNER=manual. Nothing verifies it."
        ),
    )
    parser.add_argument(
        "--operator",
        default=os.environ.get("FOSS_OPERATOR", "unknown"),
        help="Who is running this. Recorded in the audit row.",
    )
    return parser.parse_args(argv)


async def _amain(argv: Optional[list] = None) -> int:
    args = _parse_args(argv)

    # Printed before the write, not after, and only when it is actually being
    # asserted. The operator has to be able to read what they are claiming while
    # they can still Ctrl-C.
    if args.relink_done:
        print(ASSERTION, file=sys.stderr)
        print("", file=sys.stderr)

    try:
        message = await run_override(
            synthetic_id=args.synthetic_id,
            email=args.email,
            reason=args.reason,
            operator=args.operator,
            relink_done=args.relink_done,
        )
    except OverrideRefused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    finally:
        await db.close_pool()

    print(message)
    return 0


def main(argv: Optional[list] = None) -> int:
    return asyncio.run(_amain(argv))


if __name__ == "__main__":  # pragma: no cover - entry point
    sys.exit(main())
