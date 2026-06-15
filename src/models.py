"""Pydantic request and response models for launchpad-api."""
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


class EmailSubmitRequest(BaseModel):
    email: EmailStr
    display_name: Optional[str] = Field(default=None, max_length=100, min_length=1)
    consent: bool
    consent_text_version: str

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
