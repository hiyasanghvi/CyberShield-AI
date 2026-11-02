from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.analysis import Analysis
from app.models.url_analysis import URLAnalysis

from app.schemas.url_analysis import (
    URLAnalysisRequest,
    URLAnalysisResponse,
    URLHistoryResponse,
)

from app.services.url_analysis_service import analyze_url
from app.services.privacy_service import no_save_response, should_save_report


router = APIRouter(
    prefix="/api/analyze",
    tags=["URL Analysis"],
)


@router.post(
    "/url",
    response_model=URLAnalysisResponse,
)
def analyze_url_endpoint(
    request: URLAnalysisRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):

    try:
        save_report = should_save_report(http_request, db, current_user.id)
        result = analyze_url(
            url=request.url,
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

    except RuntimeError as error:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail=str(error),
        )

    except Exception as error:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"URL analysis failed: {str(error)}",
        )


@router.get(
    "/history",
    response_model=list[URLHistoryResponse],
)
def get_url_history(
    search: str | None = None,
    classification: str | None = None,
    severity: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):

    query = (
        db.query(Analysis, URLAnalysis)
        .join(
            URLAnalysis,
            URLAnalysis.analysis_id == Analysis.id
        )
        .filter(
            Analysis.user_id == current_user.id,
            Analysis.analysis_type == "URL",
        )
    )

    # Search by URL or domain
    # Classification filter
    if classification:
        query = query.filter(
            Analysis.classification == classification.upper()
        )

    # Severity filter
    if severity:
        query = query.filter(
            Analysis.severity == severity.upper()
        )

    # Keep API limit between 1 and 100
    limit = max(1, min(limit, 100))

    records = (
        query
        .order_by(Analysis.created_at.desc())
        .limit(limit)
        .all()
    )

    history = []

    for analysis, url_analysis in records:

        history.append(
            {
                "analysis_id": analysis.id,
                "url": url_analysis.url,
                "classification": analysis.classification,
                "confidence": analysis.confidence,
                "risk_score": analysis.risk_score,
                "severity": analysis.severity,
                "created_at": analysis.created_at,
            }
        )

    if search:
        needle = search.strip().casefold()
        history = [item for item in history if needle in item["url"].casefold()]

    return history
