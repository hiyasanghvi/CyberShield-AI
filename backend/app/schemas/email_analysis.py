from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class EmailAnalysisRequest(BaseModel):
    sender_email: str | None = None
    subject: str = Field(default="", max_length=500)
    body: str = Field(min_length=1, max_length=50000)
    has_attachment: bool = False
    header_data: dict[str, Any] | None = None


class EmailAnalysisResponse(BaseModel):
    analysis_id: int | None
    sender_email: str | None
    subject: str

    classification: str

    spam_probability: float
    ham_probability: float
    confidence: float

    risk_score: int
    severity: str

    explanation: str
    indicators: list[str]
    recommendation: str

    contains_url: bool
    url_count: int
    has_attachment: bool


class EmailHistoryResponse(BaseModel):
    analysis_id: int
    sender_email: str | None
    subject: str
    classification: str | None
    confidence: float | None
    risk_score: int | None
    severity: str | None
    created_at: datetime