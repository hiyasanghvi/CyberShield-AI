from pydantic import BaseModel, Field
from datetime import datetime


class SMSAnalysisRequest(BaseModel):
    text: str = Field(
        min_length=1,
        max_length=5000,
        description="SMS text to analyze",
    )


class SMSAnalysisResponse(BaseModel):
    analysis_id: int | None = None
    text: str | None = None
    classification: str
    spam_probability: float
    ham_probability: float
    confidence: float
    risk_score: int
    severity: str
    explanation: str
    indicators: list[str] | None = None
    recommendation: str


class SMSHistoryResponse(BaseModel):
    analysis_id: int
    text: str
    classification: str
    confidence: float
    risk_score: int
    severity: str
    created_at: datetime
