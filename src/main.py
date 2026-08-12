"""launchpad-api — FastAPI service for email collection and verification."""
import ipaddress
import logging
import secrets as _secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request, status
from urllib.parse import quote
from fastapi.responses import JSONResponse, RedirectResponse, Response

from src import consent_text, db
from src.gate import GateAction, decide_gate, verified_state
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
            "LAUNCHPAD_SMTP_HOST=mailpit detected. Mailpit is the dev-only "
            "fake SMTP catcher; if this is staging or production, verification "
            "emails will fail to send. See dev/docs/deploy-smtp.md for correct "
            "configuration."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
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

    return UserStateResponse(
        state="pending_verification",
        email=user["real_email"],
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

    verified, _ = await verified_state(sid, settings.gate_cache_ttl_seconds)
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
            # A programmatic caller tolerates a briefly-stale email until its
            # session refreshes; never 302 an API/MCP client.
            return Response(status_code=200)
        uri = request.headers.get("x-forwarded-uri", "/")
        rd = quote(f"{proto}://{host}{uri}", safe="")
        return RedirectResponse(
            url=f"{proto}://{host}/oauth2/sign_in?prompt=none&rd={rd}",
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
        raise HTTPException(status_code=400, detail="Unknown consent_text_version")

    token = _secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(
        hours=settings.verification_link_expiry_hours
    )

    try:
        await db.insert_user(
            synthetic_id=sid,
            email=str(payload.email),
            display_name=payload.display_name,
            verification_token=token,
            verification_expires=expires,
        )
    except db.EmailAlreadyRegistered:
        # Another account already registered this email (unique real_email
        # index). Return a terminal 409 with a clear message the frontend
        # surfaces via body.detail — not an uncaught 500 that leaves the user
        # in a hopeless retry loop.
        raise HTTPException(
            status_code=409,
            detail="This email is already registered by another account.",
        )

    await db.insert_audit(
        synthetic_id=sid,
        action="submit_email",
        email=str(payload.email),
        consent_text_version=payload.consent_text_version,
        consent_text_content=consent_text.get_text(payload.consent_text_version),
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

    # Send verification email (failures don't break submission — log and continue)
    try:
        from src.email_sender import send_verification_email
        await send_verification_email(
            to_email=str(payload.email),
            display_name=payload.display_name,
            verification_token=token,
        )
    except Exception as exc:
        # In a real implementation, log this properly. For now print.
        logger.warning("verification email send failed: %s", exc)

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
    sid = await db.mark_verified(token)

    portal = f"{settings.platform_protocol}://{settings.platform_domain}/"

    if sid is None:
        return RedirectResponse(
            url=f"{portal}?verify_error=expired_or_invalid",
            status_code=302,
        )

    await db.insert_audit(
        synthetic_id=sid,
        action="verify_email",
        email=None,
        consent_text_version=None,
        consent_text_content=None,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

    return RedirectResponse(url=f"{portal}?verified=1", status_code=302)


@app.post("/api/email/resend")
async def resend_verification(request: Request, x_auth_request_preferred_username: str = Header(default="")):
    sid = extract_synthetic_id(x_auth_request_preferred_username)
    user = await db.fetch_user(sid)

    if user is None:
        raise HTTPException(status_code=400, detail="No email submitted yet")
    if user["verified"]:
        raise HTTPException(status_code=400, detail="Already verified")

    new_token = _secrets.token_urlsafe(32)
    new_expires = datetime.now(timezone.utc) + timedelta(
        hours=settings.verification_link_expiry_hours
    )
    ok = await db.rotate_verification_token(sid, new_token, new_expires)
    if not ok:
        raise HTTPException(status_code=500, detail="Token rotation failed")

    await db.insert_audit(
        synthetic_id=sid,
        action="resend_verification",
        email=user["real_email"],
        consent_text_version=None,
        consent_text_content=None,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

    try:
        from src.email_sender import send_verification_email
        await send_verification_email(
            to_email=user["real_email"],
            display_name=user["display_name"],
            verification_token=new_token,
        )
    except Exception as exc:
        logger.warning("resend email send failed: %s", exc)

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
