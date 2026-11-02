from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.analysis import Analysis
from app.models.email_analysis import EmailAnalysis
from app.schemas.email_analysis import (
    EmailAnalysisRequest,
    EmailAnalysisResponse,
    EmailHistoryResponse,
)
from app.services.email_analysis_service import analyze_email
from app.core.security import get_current_user
from app.services.privacy_service import no_save_response, should_save_report


router = APIRouter(
    prefix="/api/analyze/email",
    tags=["Email Analysis"]
)


@router.post(
    "",
    response_model=EmailAnalysisResponse
)
def analyze_email_endpoint(
    request: EmailAnalysisRequest,
    http_request: Request,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    save_report = should_save_report(http_request, db, current_user.id)
    result = analyze_email(
        sender_email=request.sender_email,
        subject=request.subject,
        body=request.body,
        has_attachment=request.has_attachment,
        header_data=request.header_data,
        db=db,
        user_id=current_user.id,
        save_report=save_report,
    )
    return result if save_report else no_save_response(result)


@router.get(
    "/history",
    response_model=list[EmailHistoryResponse]
)
def email_history(
    search: str | None = Query(default=None),
    classification: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = (
        db.query(Analysis, EmailAnalysis)
        .join(
            EmailAnalysis,
            EmailAnalysis.analysis_id == Analysis.id
        )
        .filter(
            Analysis.user_id == current_user.id,
            Analysis.analysis_type == "EMAIL"
        )
    )

    if classification:
        query = query.filter(
            Analysis.classification == classification.upper()
        )

    if severity:
        query = query.filter(
            Analysis.severity == severity.upper()
        )

    results = (
        query
        .order_by(Analysis.created_at.desc())
        .limit(limit)
        .all()
    )

    rows = [
        {
            "analysis_id": analysis.id,
            "sender_email": email.sender_email,
            "subject": email.subject,
            "classification": analysis.classification,
            "confidence": analysis.confidence,
            "risk_score": analysis.risk_score,
            "severity": analysis.severity,
            "created_at": analysis.created_at,
        }
        for analysis, email in results
    ]
    if search:
        needle = search.casefold()
        rows = [row for row in rows if needle in " ".join(str(row.get(k) or "") for k in ("subject", "sender_email")).casefold()]
    return rows
