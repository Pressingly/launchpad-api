"""Tests for email_sender module."""
import pytest
import httpx

from src.email_sender import send_verification_email


@pytest.mark.asyncio
async def test_send_verification_email_via_mailpit():
    # Clear Mailpit inbox
    async with httpx.AsyncClient() as ac:
        await ac.delete("http://mailpit:8025/api/v1/messages")

    await send_verification_email(
        to_email="testrecipient@example.com",
        display_name="Test Recipient",
        verification_token="testtoken123",
    )

    async with httpx.AsyncClient() as ac:
        resp = await ac.get("http://mailpit:8025/api/v1/messages")
        data = resp.json()

    assert data["total"] == 1
    message = data["messages"][0]
    assert "testrecipient@example.com" in str(message["To"])
    assert "Verify your email" in message["Subject"]


async def test_send_retries_transient_failure_then_succeeds(monkeypatch, caplog):
    """Transient SMTP failure on first 2 attempts, success on third."""
    from src import email_sender

    call_count = {"n": 0}

    async def flaky_send(msg, **kwargs):
        call_count["n"] += 1
        if call_count["n"] < 3:
            raise ConnectionError("transient network blip")
        return None  # success

    # Skip real sleep to keep the test fast
    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(email_sender.aiosmtplib, "send", flaky_send)
    monkeypatch.setattr(email_sender.asyncio, "sleep", no_sleep)

    with caplog.at_level("WARNING"):
        await email_sender.send_verification_email(
            to_email="recipient@example.com",
            display_name=None,
            verification_token="testtoken123",
        )

    assert call_count["n"] == 3
    # Two warnings logged (failed attempt 1 and attempt 2; attempt 3 was success)
    warning_msgs = [r.message for r in caplog.records if r.levelname == "WARNING"]
    assert sum("SMTP send attempt" in m for m in warning_msgs) == 2


async def test_send_does_not_retry_permanent_auth_failure(monkeypatch, caplog):
    """SMTPAuthenticationError raises immediately, no retry."""
    from src import email_sender
    from aiosmtplib.errors import SMTPAuthenticationError

    call_count = {"n": 0}

    async def auth_fail_send(msg, **kwargs):
        call_count["n"] += 1
        raise SMTPAuthenticationError(535, "auth denied")

    monkeypatch.setattr(email_sender.aiosmtplib, "send", auth_fail_send)

    with pytest.raises(SMTPAuthenticationError):
        await email_sender.send_verification_email(
            to_email="recipient@example.com",
            display_name=None,
            verification_token="testtoken123",
        )

    assert call_count["n"] == 1  # No retry
