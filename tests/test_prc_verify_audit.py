"""PRD §6.1 — Verify audit (§3.2).

A mutation test showed that deleting the `verify_email` audit insert left the
whole suite passing. These are the tests that close that hole.
"""
from src import db
from tests.conftest import audit_actions, new_email, new_sid, seed_pending


async def test_verify_writes_a_verify_email_audit_row(raw_client, cleanup_test_users):
    sid = new_sid()
    await seed_pending(sid, new_email("vaudit"), "tok-audit")

    response = await raw_client.get("/api/verify?token=tok-audit", follow_redirects=False)
    assert "verified=1" in response.headers["location"]

    assert "verify_email" in await audit_actions(sid)


async def test_verify_audit_row_carries_the_client_ip(raw_client, cleanup_test_users):
    sid = new_sid()
    await seed_pending(sid, new_email("vaudit"), "tok-audit-ip")

    await raw_client.get(
        "/api/verify?token=tok-audit-ip",
        headers={"X-Forwarded-For": "203.0.113.9, 172.18.0.5"},
        follow_redirects=False,
    )

    pool = await db.get_pool()
    async with pool.acquire() as conn:
        ip = await conn.fetchval(
            "SELECT ip_address FROM foss_users_audit "
            "WHERE synthetic_id = $1 AND action = 'verify_email'",
            sid,
        )
    assert str(ip) == "203.0.113.9"


async def test_failed_verification_writes_no_audit_row(raw_client, cleanup_test_users):
    sid = new_sid()
    await seed_pending(sid, new_email("vaudit"), "tok-audit-bad")

    await raw_client.get("/api/verify?token=not-a-real-token", follow_redirects=False)

    assert await audit_actions(sid) == []
