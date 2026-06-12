from pydantic import BaseModel, Field
from typing import List, Optional


class EmailScanRequest(BaseModel):
    subject: str = Field(..., description="Email subject line")
    body: str = Field(..., description="Main email body/content")
    sender: str = Field(..., description="Sender email address")
    reply_to: Optional[str] = Field(None, description="Optional Reply-To email address")


class EmailScanResponse(BaseModel):
    risk_score: int
    label: str
    ml_score: int
    url_score: int
    metadata_score: int
    reasons: list[str]



"""
class Attachment(BaseModel):
    name: str

class ScanRequest(BaseModel):
    sender: str = ""
    reply_to: str = ""
    subject: str = ""
    body: str = Field(..., min_length=5)        #requires minimum of 5 chars 
    raw_headers: str = ""
    attachments: List[Attachment] = []

class Finding(BaseModel):
    id: str
    severity: str                               #it will be either "low" | "medium" | "high" | "critical"
    title: str
    detail: str
    evidence: Optional[str] = None 
"""

