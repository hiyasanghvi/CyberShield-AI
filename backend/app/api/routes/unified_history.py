from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.analysis import Analysis
from app.models.url_analysis import URLAnalysis
from app.models.text_analysis import TextAnalysis
from app.models.email_analysis import EmailAnalysis
from app.core.security import get_current_user
from app.services.privacy_service import purge_expired

router = APIRouter(
    prefix="/api/analyze",
    tags=["Unified Analysis"]
)


@router.get("/history")
def unified_history(
    search: str | None = Query(default=None),
    classification: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    analysis_type: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    purge_expired(db, current_user.id)
    query = (
        db.query(Analysis)
        .filter(Analysis.user_id == current_user.id)
    )

    if analysis_type:
        query = query.filter(
            Analysis.analysis_type == analysis_type.upper()
        )

    if classification:
        query = query.filter(
            Analysis.classification == classification.upper()
        )

    if severity:
        query = query.filter(
            Analysis.severity == severity.upper()
        )

    query = query.order_by(
        Analysis.created_at.desc()
    )

    analyses = query.limit(limit).all()

    results = []

    for analysis in analyses:

        item = {
            "analysis_id": analysis.id,
            "type": analysis.analysis_type,
            "classification": analysis.classification,
            "confidence": analysis.confidence,
            "risk_score": analysis.risk_score,
            "severity": analysis.severity,
            "explanation": analysis.explanation,
            "recommendation": analysis.recommendation,
            "created_at": analysis.created_at,
        }

        if analysis.analysis_type == "URL":
            url_record = (
                db.query(URLAnalysis)
                .filter(
                    URLAnalysis.analysis_id == analysis.id
                )
                .first()
            )

            if url_record:
                item["input"] = url_record.url
                item["domain"] = url_record.domain

        elif analysis.analysis_type == "SMS":
            text_record = (
                db.query(TextAnalysis)
                .filter(
                    TextAnalysis.analysis_id == analysis.id
                )
                .first()
            )

            if text_record:
                item["input"] = text_record.text_content

        elif analysis.analysis_type == "EMAIL":
            email_record = (
                db.query(EmailAnalysis)
                .filter(
                    EmailAnalysis.analysis_id == analysis.id
                )
                .first()
            )

            if email_record:
                item["input"] = email_record.subject
                item["sender_email"] = email_record.sender_email

        if search:
            search_lower = search.lower()

            searchable_values = [
                str(item.get("input", "")),
                str(item.get("domain", "")),
                str(item.get("sender_email", "")),
                str(item.get("classification", "")),
                str(item.get("type", "")),
            ]

            if not any(
                search_lower in value.lower()
                for value in searchable_values
            ):
                continue

        results.append(item)

    return {
        "total": len(results),
        "results": results,
    }
