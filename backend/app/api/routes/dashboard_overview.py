from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.analysis import Analysis
from app.core.security import get_current_user

router = APIRouter(
    prefix="/api/dashboard",
    tags=["Dashboard"],
)


@router.get("/overview")
def dashboard_overview(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    analyses = (
        db.query(Analysis)
        .filter(
            Analysis.user_id == current_user.id
        )
        .order_by(Analysis.created_at.desc())
        .all()
    )

    total = len(analyses)

    type_counts = Counter(
        item.analysis_type
        for item in analyses
    )

    classification_counts = Counter(
        item.classification
        for item in analyses
        if item.classification
    )

    severity_counts = Counter(
        item.severity
        for item in analyses
        if item.severity
    )

    risk_scores = [
        item.risk_score
        for item in analyses
        if item.risk_score is not None
    ]

    average_risk = (
        sum(risk_scores) / len(risk_scores)
        if risk_scores
        else 0
    )

    recent = analyses[:10]

    return {
        "total_scans": total,

        "total_threats": sum(
            1
            for item in analyses
            if item.classification
            in {
                "PHISHING",
                "SPAM",
                "MALICIOUS",
                "SUSPICIOUS",
            }
        ),

        "average_risk_score": round(
            average_risk,
            2,
        ),

        "analysis_types": dict(type_counts),

        "classifications": dict(
            classification_counts
        ),

        "severity_distribution": dict(
            severity_counts
        ),

        "recent_detections": [
            {
                "analysis_id": item.id,
                "type": item.analysis_type,
                "classification": item.classification,
                "risk_score": item.risk_score,
                "severity": item.severity,
                "created_at": item.created_at,
            }
            for item in recent
        ],
    }