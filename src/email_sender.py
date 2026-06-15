"""Verification email sender — talks to SMTP (Workspace in prod, Mailpit in dev)."""
from email.message import EmailMessage
from pathlib import Path
from typing import Optional

import aiosmtplib
from jinja2 import Template

from src.config import settings


TEMPLATE_DIR = Path(__file__).parent.parent / "templates"


def _render(template_name: str, **kwargs) -> str:
    path = TEMPLATE_DIR / template_name
    template = Template(path.read_text())
    return template.render(**kwargs)


async def send_verification_email(
    to_email: str,
    display_name: Optional[str],
    verification_token: str,
) -> None:
    """Send a verification email to to_email via configured SMTP."""
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

    await aiosmtplib.send(msg, **smtp_kwargs)
