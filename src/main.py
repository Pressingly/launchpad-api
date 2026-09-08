"""launchpad-api — FastAPI service for email collection and verification."""
import ipaddress
import logging
import secrets as _secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import quote

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from src import consent_text, db, rate_limit
from src.gate import GateAction, decide_gate, verified_state
from src.gate import evict as gate_evict
from src.config import settings
from src.models import EmailSubmitRequest, UserStateResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


def _warn_if_dev_smtp_in_prod(smtp_host: str) -> None:
    """Warn if SMTP_HOST looks dev-only. Mailpit is the dev-stack fake SMTP
    catcher; if this value leaks into staging or production (e.g. by inheriting
    the dev .env), verification emails will fail to deliver. Loud-and-early
    beats silent-and-late."""
    if smtp_host == "mailpit":
        logger.warning(
            "SMTP_HOST=mailpit detected (set from LAUNCHPAD_SMTP_HOST in .env "
            "under compose). Mailpit is the dev-only "
            "fake SMTP catcher; if this is staging or production, verification "
            "emails will fail to send. See dev/docs/deploy-smtp.md for correct "
            "configuration."
        )


def _require_db_password() -> None:
    """Fail loudly at startup rather than at the first request.

    launchpad-api only runs under the `launchpad` compose profile, i.e. only
    when email capture is enabled -- so reaching here with no password means a
    half-configured enable. Without this the service starts healthy (its
    healthcheck does not touch the database) and every submission 500s.
    """
    if not settings.db_password:
        raise RuntimeError(
            "DB_PASSWORD is empty. Set LAUNCHPAD_DB_PASSWORD in .env "
            "(platform.sh generates it on a fresh install; existing deployments "
            "must add it by hand -- see dev/docs/launchpad-runbook.md)."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # In lifespan rather than at import: the module must stay importable without
    # a database password so tests that do not need one can run.
    _require_db_password()
    _warn_if_dev_smtp_in_prod(settings.smtp_host)
    yield


app = FastAPI(title="launchpad-api", docs_url=None, redoc_url=None, lifespan=lifespan)


def _client_ip(request: Request) -> Optional[str]:
    """Best-effort real client IP for the consent audit record.

    Behind Traefik -> oauth2-proxy -> launchpad-api, request.client.host is the
    internal container IP (e.g. 172.18.0.x), which is useless as a consent
    record. Traefik sets X-Forwarded-For, whose left-most entry is the original
    client. Validate it before use so a malformed or spoofed header can't 500
    the audit insert (the ip_address column is cast ::inet); fall back to the
    direct peer address when there's no usable forwarded value."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        candidate = forwarded.split(",")[0].strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    return request.client.host if request.client else None


def extract_synthetic_id(x_auth_request_preferred_username: str) -> str:
    """Read the synthetic_id from the X-Auth-Request-Preferred-Username header.
    mpass-auth-proxy stamps this claim with the stable synthetic_id regardless
    of whether the user's email has been overlaid with a real address."""
    if not x_auth_request_preferred_username:
        raise HTTPException(status_code=400, detail="Missing X-Auth-Request-Preferred-Username")
    return x_auth_request_preferred_username


async def _handle_rate_limited(
    exc: rate_limit.RateLimitExceeded,
    synthetic_id: str,
    request: Request,
) -> HTTPException:
    """Turn a limiter rejection into the 429 the client sees.

    Only the platform-wide ceiling gets an audit row, and only once per day:
    rate_limit raises is_global=True solely on the first trip of each day-bucket
    (it owns the SETNX that makes that exactly-once), so this writes one row per
    day rather than one per rejected request. Per-user limits get nothing --
    they are ordinary traffic shaping and would only add noise.
    """
    if exc.is_global:
        try:
            await db.insert_audit(
                synthetic_id=synthetic_id,
                action="rate_limited",
                email=None,
                consent_text_version=None,
                consent_text_content=None,
                ip_address=_client_ip(request),
                user_agent=request.headers.get("user-agent"),
            )
        except Exception as audit_exc:
            # Never let the audit write turn a 429 into a 500.
            logger.error(
                "failed to audit global rate-limit trip: %s: %s",
                type(audit_exc).__name__, audit_exc,
            )

    minutes = max(1, -(-exc.retry_after_seconds // 60))  # ceil
    return HTTPException(
        status_code=429,
        detail=f"Too many requests. Try again in {minutes} minutes.",
        headers={"Retry-After": str(exc.retry_after_seconds)},
    )


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/me", response_model=UserStateResponse, response_model_exclude_none=True)
async def get_me(x_auth_request_preferred_username: str = Header(default="")):
    sid = extract_synthetic_id(x_auth_request_preferred_username)
    user = await db.fetch_user(sid)

    if user is None:
        return UserStateResponse(state="not_collected")

    if user["verified"]:
        return UserStateResponse(
            state="verified",
            email=user["real_email"],
            display_name=user["display_name"],
            verified_at=user["verified_at"],
        )

    # display_name is returned in both states, not just the verified one. With
    # response_model_exclude_none=True an omitted field disappears from the
    # payload entirely, so leaving it out here made the key vanish for exactly
    # the users the modal is still talking to -- a client that pre-fills the
    # form from /api/me would blank a name the user had already given.
    return UserStateResponse(
        state="pending_verification",
        email=user["real_email"],
        display_name=user["display_name"],
        verification_expires_at=user["verification_expires"],
    )


@app.get("/api/authz")
async def authz(
    request: Request,
    x_auth_request_preferred_username: str = Header(default=""),
    x_auth_request_email: str = Header(default=""),
):
    """Edge verify-gate (ADR-0018). Traefik ForwardAuth calls this after the
    mpass-auth login check on every *application* router. It never runs for the
    portal or /api/* routers, so an unverified user can always reach the
    collection flow."""
    sid = x_auth_request_preferred_username
    if not sid:
        # mpass-auth runs before this gate, so identity is always present in a
        # correct config. Its absence means a wiring mistake — fail closed.
        raise HTTPException(status_code=401, detail="missing identity")

    if not settings.synthetic_email_domain:
        # Without it, decide_gate compares against f"{sid}@" -- a string no real
        # address matches -- so REFRESH never fires and a verified user holding a
        # stale token is waved through carrying the synthetic address. That is
        # the duplicate this gate exists to prevent, so refuse rather than run
        # half-blind. mpass-auth-proxy dies at startup on the same missing value.
        logger.error(
            "authz: SYNTHETIC_EMAIL_DOMAIN is empty; refusing to gate. Set "
            "DEFAULT_EMAIL_DOMAIN in .env -- it must match mpass-auth-proxy's."
        )
        return JSONResponse(
            status_code=503,
            content={
                "error": "gate_misconfigured",
                "detail": "SYNTHETIC_EMAIL_DOMAIN is not configured.",
            },
        )

    try:
        verified, _ = await verified_state(sid, settings.gate_cache_ttl_seconds)
    except Exception as exc:
        # Fail closed, but deliberately and visibly. Unhandled, this became a
        # FastAPI 500 that Traefik copied to the client, so a launchpad DB blip
        # 500'd every gated app for every user -- including already-verified
        # ones -- with nothing but a traceback to diagnose it. The gate runs on
        # far more requests than /token does, so this path is hot.
        logger.error(
            "authz: verified-state lookup failed for sid=%s: %s: %s",
            sid, type(exc).__name__, exc,
        )
        return JSONResponse(
            status_code=503,
            content={
                "error": "verification_service_unavailable",
                "detail": "Email verification service is temporarily unavailable.",
            },
        )
    action = decide_gate(
        verified=verified,
        email=x_auth_request_email,
        sid=sid,
        synthetic_domain=settings.synthetic_email_domain,
    )
    wants_html = "text/html" in request.headers.get("accept", "")

    if action is GateAction.ALLOW:
        return Response(status_code=200)

    proto = request.headers.get("x-forwarded-proto", settings.platform_protocol)
    host = request.headers.get("x-forwarded-host", settings.platform_domain)

    if action is GateAction.REFRESH:
        if not wants_html:
            # Do NOT wave a stale programmatic caller through. This previously
            # returned 200, which handed the app the synthetic address and let
            # it create exactly the row this gate exists to prevent. The
            # standalone MCP servers are not a side channel: PLANE_BASE_URL and
            # OUTLINE_API_URL point at the public app hosts, so those tool calls
            # cross this gate with Accept: application/json and a Bearer token
            # that keeps its stale email for the token's whole lifetime. Tell
            # them to re-auth instead.
            #
            # Known carve-out, NOT covered here: `twenty-mcp-bypass`
            # (docker-compose.yml) matches /mcp, /oauth/, /.well-known/oauth and
            # /authorize -- the last being an SPA route with no server handler,
            # which redirects an unauthenticated visitor back into the gated
            # /auth/sso/proxy-login path
            # at priority 20, ahead of twenty-secure, with no mpass-auth in its
            # chain -- so no identity header reaches it and there is nothing for
            # this gate to decide on. That is Twenty's own MCP OAuth, which must
            # stay reachable unauthenticated for discovery and token exchange;
            # gating it would break the flow rather than protect it. Whether
            # that path can mint a Twenty user outside the gate is tracked
            # separately -- do not read this endpoint as blanket MCP coverage.
            return JSONResponse(
                status_code=403,
                content={
                    "error": "email_refresh_required",
                    "detail": (
                        "Your email has been verified since this token was "
                        "issued. Re-authenticate to obtain a token carrying "
                        "your verified address."
                    ),
                },
            )
        uri = request.headers.get("x-forwarded-uri", "/")
        rd = quote(f"{proto}://{host}{uri}", safe="")
        # No prompt=none: oauth2-proxy's /oauth2/sign_in does not forward query
        # parameters to the IdP authorize URL, so it was inert and merely implied
        # a silent refresh this is not. With SKIP_PROVIDER_BUTTON it goes
        # straight to doOAuthStart and keeps only `rd`. The round-trip through
        # Cognito is real; it is invisible in practice only because the IdP
        # session is still live.
        return RedirectResponse(
            url=f"{proto}://{host}/oauth2/sign_in?rd={rd}",
            status_code=302,
        )

    # action is GateAction.COLLECT
    portal = f"{settings.platform_protocol}://{settings.platform_domain}/?collect=1"
    if wants_html:
        return RedirectResponse(url=portal, status_code=302)
    return JSONResponse(
        status_code=403,
        content={"error": "email_verification_required", "verify_url": portal},
    )


@app.post("/api/email", status_code=202)
async def submit_email(
    payload: EmailSubmitRequest,
    request: Request,
    x_auth_request_preferred_username: str = Header(default=""),
):
    sid = extract_synthetic_id(x_auth_request_preferred_username)

    if not consent_text.is_valid_version(payload.consent_text_version):
        # A retired version is "known" but not acceptable -- say so, because the
        # usual cause is a cached client, and "unknown" sends the reader hunting
        # for a typo instead of reloading.
        raise HTTPException(
            status_code=400,
            detail=(
                f"consent_text_version must be {consent_text.CURRENT_VERSION}; "
                "reload the page to pick up the current consent text."
            ),
        )

    # Checked, not consumed. Quota tracks messages sent, not requests received:
    # counting the 409 below would let a stale client re-clicking an error it
    # cannot resolve walk a user -- and eventually the platform-wide ceiling --
    # into a lockout, blocking every genuine verification email for the day.
    #
    # Repeat submissions of the address the caller already holds are charged to
    # the resend bucket. They are resends in everything but name, and leaving
    # them on the submit budget was the hole that made "resend is the only
    # defence against mailing someone who never asked" untrue: a caller could
    # re-POST the same victim address on the far larger submit allowance.
    existing = await db.fetch_user(sid)
    scope = (
        "resend"
        if existing and existing["real_email"].lower() == str(payload.email).lower()
        else "submit"
    )
    try:
        await rate_limit.check(scope, sid)
    except rate_limit.RateLimitExceeded as exc:
        raise await _handle_rate_limited(exc, sid, request)

    raw_token = _secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(
        hours=settings.verification_link_expiry_hours
    )

    try:
        collision = await db.submit_email(
            synthetic_id=sid,
            email=str(payload.email),
            display_name=payload.display_name,
            # Only the hash is stored; raw_token exists solely to build the link.
            token_hash=db.hash_token(raw_token),
            verification_expires=expires,
            consent_text_version=payload.consent_text_version,
            consent_text_content=consent_text.get_text(payload.consent_text_version),
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except db.AlreadyVerified:
        # The caller's own state, which /api/me already returns to them, so this
        # discloses nothing. Refusing rather than accepting matters: the old
        # ON CONFLICT reset verified to FALSE, so one unconfirmed API call
        # downgraded a verified user and every app then saw a different
        # principal, orphaning their work.
        raise HTTPException(
            status_code=409,
            detail=(
                "This account already has a verified email address. "
                "Contact your administrator to change it."
            ),
        )

    # Deliberately no 409 for "someone else has this address". With the unique
    # index now partial, an unverified claim never collides, so the insert
    # succeeds and the response is the ordinary 202 -- the enumeration oracle
    # disappears by construction rather than by flattening the error message.
    #
    # But do not actually send when the address is already verified elsewhere.
    # The mail could only reach someone who did not ask for it, and its link is
    # useless anyway: their verification would hit the partial index. The
    # response stays a 202 so nothing leaks.
    # Consume as soon as the write has succeeded, before the collision branch.
    # The spec's rule is "count only requests that actually cause an email", but
    # its purpose is to stop *zero-effect* rejections from burning quota. A
    # collision submission is not zero-effect: it upserts a row and writes an
    # audit row. Returning before consuming would let a caller probe an
    # already-verified address without limit, each probe costing us two
    # database writes -- an amplification vector traded for the send we just
    # saved.
    await rate_limit.consume(scope, sid)

    if collision:
        logger.info("submit: address already verified elsewhere, suppressing send")
        return {
            "state": "pending_verification",
            "verification_expires_at": expires.isoformat(),
        }

    try:
        from src.email_sender import send_verification_email
        await send_verification_email(
            to_email=str(payload.email),
            display_name=payload.display_name,
            verification_token=raw_token,
        )
    except Exception as exc:
        logger.warning(
            "verification email send failed for sid=%s: %s: %s",
            sid, type(exc).__name__, exc,
        )

    return {
        "state": "pending_verification",
        "verification_expires_at": expires.isoformat(),
    }


@app.get("/api/verify")
async def verify_email(token: str, request: Request):
    # NOTE: this GET is state-mutating (consumes the one-use token). Enterprise
    # mail scanners / link-prefetchers can therefore "click" the link before the
    # user does and mark them verified early. That outcome is benign here (the
    # user still ends up verified), but if this endpoint ever gains
    # side-effects beyond verification, gate it behind an interstitial POST.
    portal = f"{settings.platform_protocol}://{settings.platform_domain}/"

    try:
        sid = await db.mark_verified(
            token_hash=db.hash_token(token),
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except db.EmailAlreadyRegistered:
        # Someone else verified this address first. Do not try to resolve it
        # automatically -- which of two accounts owns an address is a human
        # decision. Reaching this branch requires holding a valid token, which
        # was emailed to the address itself, so it is not usable as an
        # enumeration oracle by anyone who does not control that mailbox.
        logger.info("verify: address already verified by another account")
        return RedirectResponse(url=f"{portal}?verify_error=email_taken", status_code=302)

    if sid is None:
        return RedirectResponse(
            url=f"{portal}?verify_error=expired_or_invalid",
            status_code=302,
        )

    # Drop this sid from the gate's memo so the very next request re-reads the
    # database. Otherwise the user who just clicked the link is still cached as
    # unverified for up to the TTL and gets bounced back to the collection page
    # with nothing rendered to explain why.
    gate_evict(sid)

    return RedirectResponse(url=f"{portal}?verified=1", status_code=302)


@app.post("/api/email/resend")
async def resend_verification(request: Request, x_auth_request_preferred_username: str = Header(default="")):
    sid = extract_synthetic_id(x_auth_request_preferred_username)

    # After the squatting fix an unverified claim no longer blocks anyone, so a
    # claim on someone else's address simply sits there. This limit is one of
    # two things bounding how often that person can then be mailed -- the other
    # is /api/email charging repeat submissions of an address the caller already
    # holds to this same bucket (see submit_email above). Both are load-bearing;
    # raising either raises the harassment budget.
    try:
        await rate_limit.check("resend", sid)
    except rate_limit.RateLimitExceeded as exc:
        raise await _handle_rate_limited(exc, sid, request)

    raw_token = _secrets.token_urlsafe(32)
    new_expires = datetime.now(timezone.utc) + timedelta(
        hours=settings.verification_link_expiry_hours
    )

    try:
        user = await db.rotate_verification_token(
            synthetic_id=sid,
            token_hash=db.hash_token(raw_token),
            verification_expires=new_expires,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    except db.NoSubmissionYet:
        raise HTTPException(status_code=400, detail="No email submitted yet")
    except db.AlreadyVerified:
        # 409 rather than the 400 this returned previously, matching /api/email
        # for the same user state. One state, one status code.
        raise HTTPException(status_code=409, detail="Already verified")

    await rate_limit.consume("resend", sid)
    try:
        from src.email_sender import send_verification_email
        await send_verification_email(
            to_email=user["real_email"],
            display_name=user["display_name"],
            verification_token=raw_token,
        )
    except Exception as exc:
        logger.warning(
            "resend email send failed for sid=%s: %s: %s",
            sid, type(exc).__name__, exc,
        )

    return {"status": "ok"}


@app.post("/api/dismiss", status_code=410)
async def dismiss():
    """Retired. Providing a verified email is now mandatory and enforced at the
    edge by the verify-gate (ADR-0018), so there is no "dismiss" anymore. Kept
    as an explicit 410 (not deleted) so a cached frontend still calling it gets
    a clear, intentional signal rather than a 404 that reads as a routing bug."""
    raise HTTPException(
        status_code=410,
        detail="dismiss is retired; a verified email is mandatory",
    )
