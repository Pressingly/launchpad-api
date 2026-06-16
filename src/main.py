"""launchpad-api — FastAPI service for email collection and verification."""
import secrets as _secrets
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response

from src import consent_text, db
from src.config import settings
from src.models import EmailSubmitRequest, UserStateResponse

app = FastAPI(title="launchpad-api", docs_url=None, redoc_url=None)


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
        raise HTTPException(status_code=400, detail="Unknown consent_text_version")

    token = _secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(
        hours=settings.verification_link_expiry_hours
    )

    await db.insert_user(
        synthetic_id=sid,
        email=str(payload.email),
        display_name=payload.display_name,
        verification_token=token,
        verification_expires=expires,
    )

    await db.insert_audit(
        synthetic_id=sid,
        action="submit_email",
        email=str(payload.email),
        consent_text_version=payload.consent_text_version,
        consent_text_content=consent_text.get_text(payload.consent_text_version),
        ip_address=request.client.host if request.client else None,
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
        print(f"WARN: verification email send failed: {exc}")

    return {
        "state": "pending_verification",
        "verification_expires_at": expires.isoformat(),
    }


@app.get("/api/verify")
async def verify_email(token: str, request: Request):
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
        ip_address=request.client.host if request.client else None,
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
        ip_address=request.client.host if request.client else None,
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
        print(f"WARN: resend email send failed: {exc}")

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
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return Response(status_code=status.HTTP_204_NO_CONTENT)
