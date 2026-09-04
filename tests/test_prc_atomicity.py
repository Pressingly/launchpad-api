"""PRD §6.1 — Atomicity (§2.1).

The user write and the consent audit write must commit or roll back together.
The original defect took two separate pool connections, so a failing audit
insert left the platform holding a personal email address with no consent
record.

The audit write is forced to fail at the *database* level, by revoking INSERT
on foss_users_audit from the API role for the duration of the test. That is
deliberate: monkeypatching `db.insert_audit` only works while the audit write
lives in exactly that function, and §2.1 explicitly leaves the factoring to
the implementer. A permission failure fires whatever shape the code has.
"""
import pytest

from src import db
from tests.conftest import new_email, new_sid, submit


@pytest.fixture
async def audit_insert_denied(admin_conn):
    """Make every INSERT into foss_users_audit raise for launchpad_api_user.

    Permission is checked at execution time, so this takes effect on
    connections the pool already holds.
    """
    await admin_conn.execute("REVOKE INSERT ON foss_users_audit FROM launchpad_api_user")
    try:
        yield
    finally:
        await admin_conn.execute("GRANT INSERT ON foss_users_audit TO launchpad_api_user")


async def test_audit_failure_leaves_no_user_row(
    raw_client, cleanup_test_users, audit_insert_denied
):
    sid = new_sid()
    email = new_email("atomic")

    response = await submit(raw_client, sid, email)

    # The request fails — that is fine and expected. What must not happen is a
    # committed foss_users row with no matching consent record.
    # Assert the specific status a failing audit insert produces, not merely
    # "not 202". The looser form is satisfied by any rejection that happens
    # before the write -- add a validation rule, or let a 429 land earlier, and
    # this test would pass while never exercising the revoked audit insert at
    # all.
    assert response.status_code == 500

    user = await db.fetch_user(sid)
    assert user is None, (
        "the audit insert failed but a foss_users row was committed anyway: "
        "the two writes are not in one transaction (§2.1)"
    )


async def test_audit_failure_leaves_no_row_even_on_a_repeat_submit(
    raw_client, cleanup_test_users, admin_conn
):
    """The rollback must also protect an existing unverified row's address.

    A first submit succeeds; a second submit whose audit write fails must not
    leave the row pointing at the new address.
    """
    sid = new_sid()
    first_email = new_email("atomic-a")
    second_email = new_email("atomic-b")

    assert (await submit(raw_client, sid, first_email)).status_code == 202

    await admin_conn.execute("REVOKE INSERT ON foss_users_audit FROM launchpad_api_user")
    try:
        response = await submit(raw_client, sid, second_email)
    finally:
        await admin_conn.execute("GRANT INSERT ON foss_users_audit TO launchpad_api_user")

    # Assert the specific status a failing audit insert produces, not merely
    # "not 202". The looser form is satisfied by any rejection that happens
    # before the write -- add a validation rule, or let a 429 land earlier, and
    # this test would pass while never exercising the revoked audit insert at
    # all.
    assert response.status_code == 500
    user = await db.fetch_user(sid)
    assert user is not None
    assert user["real_email"] == first_email, (
        "the failed submit's UPDATE was committed without its audit row (§2.1)"
    )
