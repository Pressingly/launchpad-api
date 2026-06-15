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
