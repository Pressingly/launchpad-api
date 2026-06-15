"""Tests for Pydantic request/response models."""
import pytest
from pydantic import ValidationError

from src.models import EmailSubmitRequest, UserStateResponse


def test_email_submit_request_accepts_valid():
    req = EmailSubmitRequest(
        email="jane.doe@example.com",
        display_name="Jane Doe",
        consent=True,
        consent_text_version="v1.0",
    )
    assert req.email == "jane.doe@example.com"


def test_email_submit_request_rejects_invalid_email():
    with pytest.raises(ValidationError):
        EmailSubmitRequest(
            email="not-an-email",
            display_name=None,
            consent=True,
            consent_text_version="v1.0",
        )


def test_email_submit_request_requires_consent_true():
    with pytest.raises(ValidationError):
        EmailSubmitRequest(
            email="jane.doe@example.com",
            display_name=None,
            consent=False,
            consent_text_version="v1.0",
        )


def test_email_submit_request_display_name_max_length():
    with pytest.raises(ValidationError):
        EmailSubmitRequest(
            email="jane.doe@example.com",
            display_name="a" * 101,
            consent=True,
            consent_text_version="v1.0",
        )


def test_user_state_response_not_collected():
    resp = UserStateResponse(state="not_collected")
    assert resp.model_dump(exclude_none=True) == {"state": "not_collected"}
