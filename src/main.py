"""launchpad-api — FastAPI service for email collection and verification."""
from fastapi import FastAPI, Header, HTTPException

from src import db
from src.models import UserStateResponse

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
