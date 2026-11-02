from pydantic import BaseModel, Field
from datetime import datetime

class URLAnalysisRequest(BaseModel):
    url: str = Field(
        min_length=3,
        max_length=2048,
        description="URL to analyze"
    )


class URLAnalysisResponse(BaseModel):
    analysis_id: int | None = None
    url: str | None = None
    classification: str
    phishing_probability: float
    legitimate_probability: float
    confidence: float
    risk_score: int
    severity: str
    explanation: str
    indicators: list[str] | None = None
    recommendation: str

class URLHistoryResponse(BaseModel):
    analysis_id: int
    url: str
    classification: str
    confidence: float
    risk_score: int
    severity: str
    created_at: datetime
