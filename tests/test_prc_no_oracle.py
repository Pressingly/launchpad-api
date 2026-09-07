"""PRD §6.1 — No enumeration oracle (§2.2).

Submitting an address another account has already *verified* must look exactly
like an ordinary submission to the caller, while leaving a distinguishable
trace for an operator: a `submit_email_collision` audit row written *instead
of* the usual `submit_email` row.
"""
import re

from tests.conftest import audit_actions, new_email, new_sid, seed_pending, submit

# The 202 body carries a timestamp, so "byte-identical" (§6.1) can only mean
# identical once that timestamp is normalised — two responses are microseconds
# apart by construction.
_TS = re.compile(r'"verification_expires_at"\s*:\s*"[^"]*"')


def _normalised(response) -> bytes:
    return _TS.sub('"verification_expires_at":"<ts>"', response.text).encode()


async def test_collision_submit_returns_ordinary_202_body(raw_client, cleanup_test_users):
    email = new_email("oracle")
    victim, attacker, control = new_sid(), new_sid(), new_sid()

    await seed_pending(victim, email, "tok-victim")
    verified = await raw_client.get("/api/verify?token=tok-victim", follow_redirects=False)
    assert "verified=1" in verified.headers.get("location", "")

    collision = await submit(raw_client, attacker, email)
    ordinary = await submit(raw_client, control, new_email("ordinary"))

    assert collision.status_code == 202
    assert ordinary.status_code == 202
    assert collision.json().keys() == ordinary.json().keys()
    assert collision.json()["state"] == ordinary.json()["state"] == "pending_verification"
    assert _normalised(collision) == _normalised(ordinary)


async def test_collision_writes_submit_email_collision_audit_row(
    raw_client, cleanup_test_users
):
    email = new_email("oracle")
    victim, attacker = new_sid(), new_sid()

    await seed_pending(victim, email, "tok-victim2")
    await raw_client.get("/api/verify?token=tok-victim2", follow_redirects=False)

    assert (await submit(raw_client, attacker, email)).status_code == 202
    assert "submit_email_collision" in await audit_actions(attacker)


async def test_collision_does_not_write_a_submit_email_audit_row(
    raw_client, cleanup_test_users
):
    """Replace-not-supplement (§2.2): a probe must never be recorded as consent."""
    email = new_email("oracle")
    victim, attacker = new_sid(), new_sid()

    await seed_pending(victim, email, "tok-victim3")
    await raw_client.get("/api/verify?token=tok-victim3", follow_redirects=False)

    assert (await submit(raw_client, attacker, email)).status_code == 202
    assert "submit_email" not in await audit_actions(attacker)


async def test_collision_audit_row_keeps_consent_text_for_forensics(
    raw_client, cleanup_test_users
):
    from src import consent_text, db

    email = new_email("oracle")
    victim, attacker = new_sid(), new_sid()
    await seed_pending(victim, email, "tok-victim4")
    await raw_client.get("/api/verify?token=tok-victim4", follow_redirects=False)
    await submit(raw_client, attacker, email)

    pool = await db.get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT consent_text_version, consent_text_content, email "
            "FROM foss_users_audit "
            "WHERE synthetic_id = $1 AND action = 'submit_email_collision'",
            attacker,
        )
    assert row is not None
    assert row["consent_text_version"] == consent_text.CURRENT_VERSION
    assert row["consent_text_content"] == consent_text.get_text(consent_text.CURRENT_VERSION)
    assert row["email"] == email
