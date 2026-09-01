"""launchpad-api — FastAPI service for email collection and verification."""
import ipaddress
import logging
import secrets as _secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response

from src import consent_text, db
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


@app.post("/api/dismiss", status_code=204)
async def dismiss(request: Request, x_auth_request_preferred_username: str = Header(default="")):
    sid = extract_synthetic_id(x_auth_request_preferred_username)

    await db.insert_audit(
        synthetic_id=sid,
        action="dismiss_modal",
        email=None,
        consent_text_version=None,
        consent_text_content=None,
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)
