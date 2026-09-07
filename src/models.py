"""Pydantic request and response models for launchpad-api."""
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


class EmailSubmitRequest(BaseModel):
    email: EmailStr
    display_name: Optional[str] = Field(default=None, max_length=100, min_length=1)
    consent: bool
    consent_text_version: str

    @field_validator("display_name", mode="before")
    @classmethod
    def normalise_display_name(cls, v):
        """Treat a blank display name as absent, and refuse control characters.

        Two separate concerns, deliberately in one `mode="before"` validator so
        both run ahead of the `Field` constraints (which is what lets
        `min_length=1` stay: `""` never reaches it, and 101 characters still
        trip `max_length`).

        Blank -> None: the field is optional, and a browser sends an untouched
        text input as `""`, not `null`. Rejecting that with a 422
        `string_too_short` fails a submission over a field the user chose to
        leave empty.

        Control characters -> rejected: `display_name` is interpolated into
        `templates/verify_email.txt`, and `select_autoescape(["html"])` does not
        escape a .txt template. A name containing CR/LF therefore injects
        attacker-chosen lines into a plaintext email sent from our own domain --
        header- and body-spoofing in a message the recipient has every reason to
        trust. Suppressing the send on a verified-elsewhere collision narrowed
        the reach but did not close it: a submission for an address nobody has
        verified yet still sends.
        """
        if isinstance(v, str):
            if v == "":
                return None
            if any(ord(c) < 0x20 or ord(c) == 0x7F for c in v):
                raise ValueError(
                    "display_name must not contain newlines or control characters"
                )
        return v

    @field_validator("consent")
    @classmethod
    def consent_must_be_true(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError("consent must be true")
        return v


class UserStateResponse(BaseModel):
    state: Literal["not_collected", "pending_verification", "verified"]
    email: Optional[str] = None
    display_name: Optional[str] = None
    verification_expires_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None
