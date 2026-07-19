from datetime import UTC, datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class UserCredentials(BaseModel):
    username: str = Field(..., min_length=3, description="Username")
    password: str = Field(..., min_length=8, description="Password")


class UserResponse(BaseModel):
    username: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class EmailScanRequest(BaseModel):
    subject: str = Field(..., description="Email subject line")
    body: str = Field(..., description="Main email body/content")
    sender: str = Field(..., description="Sender email address")
    reply_to: Optional[str] = Field(None, description="Optional Reply-To email address")


class ScanExplanation(BaseModel):
    ml: list[str] = Field(default_factory=list)
    nlp: list[str] = Field(default_factory=list)
    url: list[str] = Field(default_factory=list)
    metadata: list[str] = Field(default_factory=list)


class EmailScanResponse(BaseModel):
    risk_score: int
    label: str
    ml_score: int
    nlp_score: int
    url_score: int
    metadata_score: int
    reasons: list[str]
    ml_suspicious_words: list[str] = Field(default_factory=list)
    explanation: ScanExplanation = Field(default_factory=ScanExplanation)


class ScanHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    subject: str
    sender: str
    reply_to: Optional[str]
    body_preview: str

    risk_score: int
    label: str

    ml_score: int
    nlp_score: int
    url_score: int
    metadata_score: int

    reasons: list[str]
    created_at: datetime

    @field_validator("created_at", mode="before")
    @classmethod
    def treat_sqlite_timestamp_as_utc(cls, value):
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=UTC)

        return value
