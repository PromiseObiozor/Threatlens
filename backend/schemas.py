from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime



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


class EmailScanResponse(BaseModel):
    risk_score: int
    label: str
    ml_score: int
    nlp_score: int
    url_score: int
    metadata_score: int
    reasons: list[str]


class ScanHistoryResponse(BaseModel):
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

    class Config:
        from_attributes = True



