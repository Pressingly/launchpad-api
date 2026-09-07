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


def test_email_submit_request_blank_display_name_becomes_none():
    """An untouched text input arrives as "", not null.

    Before the coercion this was a 422 `string_too_short` on an *optional*
    field: the submission failed because the user declined to fill in something
    optional. Omitted and null already produced None; "" now joins them.
    """
    req = EmailSubmitRequest(
        email="jane.doe@example.com",
        display_name="",
        consent=True,
        consent_text_version="v1.0",
    )
    assert req.display_name is None


def test_email_submit_request_null_and_omitted_display_name_still_none():
    explicit = EmailSubmitRequest(
        email="jane.doe@example.com",
        display_name=None,
        consent=True,
        consent_text_version="v1.0",
    )
    omitted = EmailSubmitRequest(
        email="jane.doe@example.com",
        consent=True,
        consent_text_version="v1.0",
    )
    assert explicit.display_name is None
    assert omitted.display_name is None


@pytest.mark.parametrize(
    "bad",
    [
        "Jane\nBcc: victim@example.com",
        "Jane\rDoe",
        "Jane\r\nDoe",
        "Jane\tDoe",
        "Jane\x00Doe",
        "Jane\x7fDoe",
    ],
)
def test_email_submit_request_rejects_control_characters(bad):
    """display_name lands in templates/verify_email.txt, which Jinja's
    select_autoescape(["html"]) does not escape. A newline there writes
    attacker-chosen lines into a plaintext mail sent from our own domain."""
    with pytest.raises(ValidationError):
        EmailSubmitRequest(
            email="jane.doe@example.com",
            display_name=bad,
            consent=True,
            consent_text_version="v1.0",
        )


def test_user_state_response_pending_carries_display_name():
    resp = UserStateResponse(
        state="pending_verification",
        email="jane@example.com",
        display_name="Jane",
    )
    assert resp.model_dump(exclude_none=True)["display_name"] == "Jane"
