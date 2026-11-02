from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.analysis import Analysis
from app.models.text_analysis import TextAnalysis

from app.schemas.sms_analysis import (
    SMSAnalysisRequest,
    SMSAnalysisResponse,
    SMSHistoryResponse,
)

from app.services.sms_analysis_service import analyze_sms
from app.services.privacy_service import no_save_response, should_save_report


router = APIRouter(
    prefix="/api/analyze",
    tags=["SMS Analysis"],
)


@router.post(
    "/sms",
    response_model=SMSAnalysisResponse,
)
def analyze_sms_endpoint(
    request: SMSAnalysisRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):

    try:

        save_report = should_save_report(http_request, db, current_user.id)
        result = analyze_sms(
            text=request.text,
            db=db,
            user_id=current_user.id,
            save_report=save_report,
        )
        return result if save_report else no_save_response(result)

    except HTTPException:
        raise

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except Exception as error:

        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"SMS analysis failed: {str(error)}",
        )


@router.get(
    "/sms/history",
    response_model=list[SMSHistoryResponse],
)
def get_sms_history(
    search: str | None = None,
    classification: str | None = None,
    severity: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):

    query = (
        db.query(Analysis, TextAnalysis)
        .join(
            TextAnalysis,
            TextAnalysis.analysis_id == Analysis.id,
        )
        .filter(
            Analysis.user_id == current_user.id,
            Analysis.analysis_type == "SMS",
        )
    )

    if classification:

        query = query.filter(
            Analysis.classification
            == classification.upper()
        )

    if severity:

        query = query.filter(
            Analysis.severity
            == severity.upper()
        )

    limit = max(
        1,
        min(limit, 100),
    )

    records = (
        query
        .order_by(
            Analysis.created_at.desc()
        )
        .limit(limit)
        .all()
    )

    history = []

    for analysis, text_analysis in records:

        history.append(
            {
                "analysis_id": analysis.id,
                "text": text_analysis.text_content,
                "classification": analysis.classification,
                "confidence": analysis.confidence,
                "risk_score": analysis.risk_score,
                "severity": analysis.severity,
                "created_at": analysis.created_at,
            }
        )

    if search:
        needle = search.strip().casefold()
        history = [item for item in history if needle in str(item.get("text") or "").casefold()]
    return history
