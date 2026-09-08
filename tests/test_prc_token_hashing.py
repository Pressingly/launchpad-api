"""PRD §6.1 — Token hashing (§1.2, §3.1).

The verification token is a bearer credential: anything that can read the
column can complete verification for any pending user. The column therefore
stores sha256(raw) as lowercase hex, and only the raw value ever leaves the
service — in the emailed link.
"""
import re

from src import db
from tests.conftest import (
    latest_token,
    mailpit_messages,
    new_email,
    new_sid,
    sha256_hex,
    submit,
)

HEX64 = re.compile(r"^[0-9a-f]{64}$")


async def test_stored_token_is_never_the_emailed_token(
    client, cleanup_test_users, clean_mailbox
):
    sid = new_sid()
    assert (await submit(client, sid, new_email("hash"))).status_code == 202

    raw = await latest_token()
    stored = (await db.fetch_user(sid))["verification_token"]

    assert stored != raw, "the raw bearer token is stored in the database"
    assert stored == sha256_hex(raw)


async def test_verification_succeeds_with_the_raw_token_from_the_link(
    client, cleanup_test_users, clean_mailbox
):
    sid = new_sid()
    assert (await submit(client, sid, new_email("hash"))).status_code == 202
    raw = await latest_token()

    response = await client.get(f"/api/verify?token={raw}", follow_redirects=False)

    assert response.status_code == 302
    assert "relinking=1" in response.headers["location"]
    assert (await db.fetch_user(sid))["relink_state"] == "pending_relink"


async def test_stored_token_is_64_lowercase_hex_characters(
    client, cleanup_test_users, clean_mailbox
):
    sid = new_sid()
    assert (await submit(client, sid, new_email("hash"))).status_code == 202

    stored = (await db.fetch_user(sid))["verification_token"]

    assert HEX64.match(stored or ""), f"not a lowercase sha256 hex digest: {stored!r}"


async def test_the_stored_digest_is_not_itself_a_usable_token(
    client, cleanup_test_users, clean_mailbox
):
    """Leaked read-only access to the column must not be replayable (§1.2)."""
    sid = new_sid()
    assert (await submit(client, sid, new_email("hash"))).status_code == 202
    stored = (await db.fetch_user(sid))["verification_token"]

    response = await client.get(f"/api/verify?token={stored}", follow_redirects=False)

    assert "verify_error=expired_or_invalid" in response.headers["location"]
    user = await db.fetch_user(sid)
    assert user["verified"] is False
    assert user["relink_state"] == "none"


async def test_resend_also_stores_a_hash_not_the_emailed_value(
    client, cleanup_test_users, clean_mailbox
):
    sid = new_sid()
    assert (await submit(client, sid, new_email("hash"))).status_code == 202
    await client.post("/api/email/resend", headers={"X-Auth-Request-Preferred-Username": sid})

    messages = await mailpit_messages()
    assert len(messages) == 2
    raw = await latest_token()
    stored = (await db.fetch_user(sid))["verification_token"]

    assert stored != raw
    assert stored == sha256_hex(raw)
