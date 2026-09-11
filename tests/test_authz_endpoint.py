"""Integration tests for the edge verify-gate endpoint GET /api/authz."""
import secrets
import urllib.parse
from datetime import timedelta, timezone

import pytest

from src import db, gate
from src.config import settings

# Build synthetic addresses from the configured domain, never a hardcoded one.
# Hardcoding "askii.ai" made these tests pass against a mis-wired service: with
# SYNTHETIC_EMAIL_DOMAIN set to anything else the comparison in decide_gate
# stopped matching, REFRESH became unreachable, and the stale-token cases
# silently took the ALLOW path instead.
_SYNTH = settings.synthetic_email_domain


# No local cleanup_test_users fixture: conftest provides one that deletes
# foss_users through the ordinary pool and foss_users_audit over the superuser
# connection. The audit table deliberately does not grant DELETE to
# launchpad_api_user (it is an append-only action history), so a local fixture
# using the app pool fails with InsufficientPrivilegeError at teardown.


async def _mk_relinked(sid: str, email: str):
    """Seed a user whose relink is COMPLETE -- the only kind the gate lets
    through.

    Clicking the verification link no longer produces this state; it produces
    pending_relink. Tokens are stored hashed, so the calls take a digest rather
    than the raw value; db.hash_token is the same function the endpoints use.
    """
    from datetime import datetime

    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    token_hash = db.hash_token("tok_" + sid)
    await db.submit_email(
        synthetic_id=sid,
        email=email,
        display_name="Jane",
        token_hash=token_hash,
        verification_expires=expires,
        consent_text_version="test",
        consent_text_content="test consent",
        ip_address=None,
        user_agent=None,
    )
    assert await db.mark_pending_relink(token_hash, ip_address=None, user_agent=None) == sid
    assert await db.mark_relinked(sid) is True


async def _mk_pending_relink(sid: str, email: str):
    """Seed a user held mid-relink: the link is clicked, the relink is not
    done."""
    from datetime import datetime

    expires = datetime.now(timezone.utc) + timedelta(hours=24)
    token_hash = db.hash_token("tok_" + sid)
    await db.submit_email(
        synthetic_id=sid,
        email=email,
        display_name="Jane",
        token_hash=token_hash,
        verification_expires=expires,
        consent_text_version="test",
        consent_text_content="test consent",
        ip_address=None,
        user_agent=None,
    )
    assert await db.mark_pending_relink(token_hash, ip_address=None, user_agent=None) == sid


async def test_authz_allows_verified_real_email(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    await _mk_relinked(sid, "jane@corp.com")
    gate._clear_cache()
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Preferred-Username": sid,
            "X-Auth-Request-Email": "jane@corp.com",
            "Accept": "text/html",
        },
    )
    assert r.status_code == 200


async def test_authz_redirects_unverified_browser_to_collect(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    gate._clear_cache()
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Preferred-Username": sid,
            "X-Auth-Request-Email": f"{sid}@{_SYNTH}",
            "Accept": "text/html",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "/?collect=1" in r.headers["location"]


async def test_authz_403_json_for_unverified_api_client(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    gate._clear_cache()
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Preferred-Username": sid,
            "X-Auth-Request-Email": f"{sid}@{_SYNTH}",
            "Accept": "application/json",
        },
    )
    assert r.status_code == 403
    assert r.json()["error"] == "email_verification_required"
    assert "verify_url" in r.json()


async def test_authz_refreshes_stale_synthetic_token(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    await _mk_relinked(sid, "jane@corp.com")  # verified in DB...
    gate._clear_cache()
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Preferred-Username": sid,
            "X-Auth-Request-Email": f"{sid}@{_SYNTH}",  # ...but token still synthetic
            "Accept": "text/html",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "pm.foss.local.dev",
            "X-Forwarded-Uri": "/projects",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    loc = r.headers["location"]
    # Assert the path and rd only. prompt=none used to sit between them and did
    # nothing -- oauth2-proxy drops query params on /oauth2/sign_in -- so pinning
    # it here would re-enshrine a dead parameter.
    assert loc.startswith("https://pm.foss.local.dev/oauth2/sign_in?")
    assert "rd=" in loc
    rd = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)["rd"]
    assert rd == ["https://pm.foss.local.dev/projects"]


async def test_authz_refuses_stale_token_for_api_client(client, cleanup_test_users):
    """A programmatic caller with a stale token must re-authenticate, not be
    waved through. Returning 200 here handed the app the synthetic address and
    let it create exactly the duplicate row this gate exists to prevent -- and
    MCP traffic crosses this gate, holding one token for its whole lifetime."""
    sid = f"test_{secrets.token_hex(4)}"
    await _mk_relinked(sid, "jane@corp.com")
    gate._clear_cache()
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Preferred-Username": sid,
            "X-Auth-Request-Email": f"{sid}@{_SYNTH}",
            "Accept": "application/json",
        },
    )
    assert r.status_code == 403
    assert r.json()["error"] == "email_refresh_required"


async def test_authz_redirects_a_relinking_browser_to_the_relinking_panel(
    client, cleanup_test_users
):
    """Held, not collected. Sending them to ?collect=1 shows the collection
    form, which invites a resubmit that lands them right back here."""
    sid = f"test_{secrets.token_hex(4)}"
    await _mk_pending_relink(sid, f"relink-{secrets.token_hex(4)}@corp.com")
    gate._clear_cache()
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Preferred-Username": sid,
            "X-Auth-Request-Email": f"{sid}@{_SYNTH}",
            "Accept": "text/html",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "/?relinking=1" in r.headers["location"]
    assert "collect=1" not in r.headers["location"]


async def test_authz_403_json_for_a_relinking_api_client(client, cleanup_test_users):
    sid = f"test_{secrets.token_hex(4)}"
    await _mk_pending_relink(sid, f"relink-{secrets.token_hex(4)}@corp.com")
    gate._clear_cache()
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Preferred-Username": sid,
            "X-Auth-Request-Email": f"{sid}@{_SYNTH}",
            "Accept": "application/json",
        },
    )
    assert r.status_code == 403
    assert r.json()["error"] == "relink_in_progress"


async def test_authz_holds_a_relinking_user_even_with_a_real_email_claim(
    client, cleanup_test_users
):
    """The population this gate exists for. If a token somehow already carried
    the real address, letting them through is what creates the duplicate app
    account -- so the hold is decided on state, never on the claim."""
    sid = f"test_{secrets.token_hex(4)}"
    await _mk_pending_relink(sid, f"relink-{secrets.token_hex(4)}@corp.com")
    gate._clear_cache()
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Preferred-Username": sid,
            "X-Auth-Request-Email": "jane@corp.com",
            "Accept": "text/html",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    assert "/?relinking=1" in r.headers["location"]


async def test_authz_allows_the_legacy_verified_combination(
    client, cleanup_test_users
):
    """verified = true, relink_state = 'none': verified before the column
    existed. Holding them would lock out accounts that predate the feature."""
    sid = f"test_{secrets.token_hex(4)}"
    await _mk_relinked(sid, "legacy@corp.com")
    pool = await db.get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE foss_users SET relink_state = 'none' WHERE synthetic_id = $1",
            sid,
        )
    gate._clear_cache()
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Preferred-Username": sid,
            "X-Auth-Request-Email": "legacy@corp.com",
            "Accept": "text/html",
        },
    )
    assert r.status_code == 200


async def test_authz_503s_when_synthetic_domain_is_unset(client, monkeypatch):
    """An empty domain makes decide_gate compare against f"{sid}@", which no
    real address matches -- REFRESH would never fire and every stale-token user
    would be waved through with the synthetic address. Refuse instead."""
    monkeypatch.setattr(settings, "synthetic_email_domain", "")
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Preferred-Username": "test_whatever",
            "X-Auth-Request-Email": "test_whatever@anything",
            "Accept": "application/json",
        },
    )
    assert r.status_code == 503
    assert r.json()["error"] == "gate_misconfigured"


async def test_authz_missing_identity_is_401(client):
    r = await client.get("/api/authz", headers={"Accept": "text/html"})
    assert r.status_code == 401


async def test_authz_stale_session_redirects_once(client):
    """No preferred_username but the other three identity headers are present
    -- oauth2-proxy authenticated the session before mpass-auth-proxy started
    re-signing tokens with the claim. Send the browser to sign_in rather than
    dead-ending with a 401 it can't recover from."""
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Email": "jane@corp.com",
            "X-Auth-Request-User": "jane@corp.com",
            "X-Auth-Request-Access-Token": "tok_abc",
            "Accept": "text/html",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "pm.foss.local.dev",
            "X-Forwarded-Uri": "/projects",
        },
        follow_redirects=False,
    )
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith("https://pm.foss.local.dev/oauth2/sign_in?")
    rd = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)["rd"]
    assert rd == ["https://pm.foss.local.dev/projects?launchpad_stale_retry=1"]


async def test_authz_stale_session_api_client_gets_403(client):
    """Same missing-claim case for a programmatic caller: no auto-redirect
    possible, so tell it to re-authenticate instead."""
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Email": "jane@corp.com",
            "Accept": "application/json",
        },
    )
    assert r.status_code == 403
    assert r.json()["error"] == "stale_session"


async def test_authz_second_arrival_still_missing_identity_falls_through_to_401(client):
    """The retry marker comes back on X-Forwarded-Uri after a completed
    sign_in round trip. If preferred_username is STILL absent, re-login did
    not fix it -- this is not a stale session, so fail closed exactly like the
    original 401 rather than redirecting forever."""
    r = await client.get(
        "/api/authz",
        headers={
            "X-Auth-Request-Email": "jane@corp.com",
            "Accept": "text/html",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "pm.foss.local.dev",
            "X-Forwarded-Uri": "/projects?launchpad_stale_retry=1",
        },
        follow_redirects=False,
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "missing identity"


async def test_authz_all_identity_headers_absent_still_401s_immediately(client):
    """No preferred_username and none of the other three headers either --
    mpass-auth never ran at all. A genuine wiring fault, not a stale session:
    fail closed immediately, no redirect."""
    r = await client.get(
        "/api/authz",
        headers={
            "Accept": "text/html",
            "X-Forwarded-Uri": "/projects",
        },
        follow_redirects=False,
    )
    assert r.status_code == 401
    assert r.json()["detail"] == "missing identity"
