"""launchpad-api — FastAPI service for email collection and verification."""
import secrets as _secrets
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import RedirectResponse

from src import consent_text, db
from src.config import settings
from src.models import EmailSubmitRequest, UserStateResponse

app = FastAPI(title="launchpad-api", docs_url=None, redoc_url=None)


def extract_synthetic_id(x_auth_request_email: str) -> str:
    """Extract the synthetic ID portion from the X-Auth-Request-Email header.
    Expected format: <synthetic_id>@askii.ai"""
    if not x_auth_request_email or "@" not in x_auth_request_email:
        raise HTTPException(status_code=400, detail="Invalid X-Auth-Request-Email")
    return x_auth_request_email.split("@", 1)[0]


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/me", response_model=UserStateResponse, response_model_exclude_none=True)
async def get_me(x_auth_request_email: str = Header(default="")):
    sid = extract_synthetic_id(x_auth_request_email)
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
    x_auth_request_email: str = Header(default=""),
):
    sid = extract_synthetic_id(x_auth_request_email)

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
