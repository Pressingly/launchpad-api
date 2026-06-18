"""Verification email sender — talks to SMTP (Workspace in prod, Mailpit in dev)."""
import asyncio
import logging
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

import aiosmtplib
from aiosmtplib.errors import SMTPRecipientsRefused, SMTPAuthenticationError
from jinja2 import Template

from src.config import settings


logger = logging.getLogger(__name__)
TEMPLATE_DIR = Path(__file__).parent.parent / "templates"

# Permanent errors that won't be retried — retrying would just burn time
# and risk getting flagged by the SMTP relay. These two cover the realistic
# permanent-failure surface: auth misconfig and 5xx recipient refused.
_PERMANENT_SMTP_ERRORS = (SMTPRecipientsRefused, SMTPAuthenticationError)

_MAX_ATTEMPTS = 3
_INITIAL_BACKOFF_SECONDS = 1.0


def _render(template_name: str, **kwargs) -> str:
    path = TEMPLATE_DIR / template_name
    template = Template(path.read_text())
    return template.render(**kwargs)


async def _send_with_retry(msg: EmailMessage, smtp_kwargs: dict) -> None:
    """Send via aiosmtplib with bounded retries on transient failures.

    Retries up to _MAX_ATTEMPTS times with exponential backoff. Permanent
    errors (_PERMANENT_SMTP_ERRORS) raise immediately without retry.
    """
    last_exc: Optional[Exception] = None
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            await aiosmtplib.send(msg, **smtp_kwargs)
            if attempt > 1:
                logger.info("SMTP send succeeded on attempt %d/%d", attempt, _MAX_ATTEMPTS)
            return
        except _PERMANENT_SMTP_ERRORS:
            raise
        except Exception as exc:
            last_exc = exc
            if attempt < _MAX_ATTEMPTS:
                wait = _INITIAL_BACKOFF_SECONDS * (2 ** (attempt - 1))
                logger.warning(
                    "SMTP send attempt %d/%d failed: %s; retrying in %.1fs",
                    attempt, _MAX_ATTEMPTS, exc, wait,
                )
                await asyncio.sleep(wait)
            else:
                logger.error(
                    "SMTP send failed after %d attempts: %s",
                    _MAX_ATTEMPTS, exc,
                )
    if last_exc is not None:
        raise last_exc


async def send_verification_email(
    to_email: str,
    display_name: Optional[str],
    verification_token: str,
) -> None:
    """Send a verification email to to_email via configured SMTP.
    Retries transient failures up to 3 times with exponential backoff."""
    verification_url = f"{settings.verification_url_base}?token={verification_token}"

    text_body = _render(
        "verify_email.txt",
        display_name=display_name,
        verification_url=verification_url,
        expiry_hours=settings.verification_link_expiry_hours,
    )
    html_body = _render(
        "verify_email.html",
        display_name=display_name,
        verification_url=verification_url,
        expiry_hours=settings.verification_link_expiry_hours,
    )

    msg = EmailMessage()
    msg["From"] = f"{settings.from_name} <{settings.from_address}>"
    msg["To"] = to_email
    msg["Subject"] = "Verify your email — FOSS Launchpad"
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    smtp_kwargs = dict(
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        use_tls=False,
        start_tls=settings.smtp_use_tls,
    )
    if settings.smtp_user:
        smtp_kwargs["username"] = settings.smtp_user
        smtp_kwargs["password"] = settings.smtp_password

    await _send_with_retry(msg, smtp_kwargs)
