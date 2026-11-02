from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.analysis import Analysis
from app.services.privacy_service import purge_expired
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
    purge_expired(db, current_user.id)
    analyses = (
        db.query(Analysis)
        .filter(
            Analysis.user_id == current_user.id
        )
        .order_by(
            Analysis.created_at.desc()
        )
        .all()
    )

    total_scans = len(analyses)

    # Analysis type distribution
    type_counts = Counter(
        analysis.analysis_type
        for analysis in analyses
    )

    # Classification distribution
    classification_counts = Counter(
        analysis.classification
        for analysis in analyses
        if analysis.classification
    )

    # Severity distribution
    severity_counts = Counter(
        analysis.severity
        for analysis in analyses
        if analysis.severity
    )

    # Average risk score
    risk_scores = [
        analysis.risk_score
        for analysis in analyses
        if analysis.risk_score is not None
    ]

    average_risk_score = (
        sum(risk_scores) / len(risk_scores)
        if risk_scores
        else 0
    )

    # Count known threats
    threat_classifications = {
        "PHISHING",
        "SPAM",
        "MALICIOUS",
        "SUSPICIOUS",
    }

    total_threats = sum(
        1
        for analysis in analyses
        if analysis.classification
        in threat_classifications
    )

    # Recent detections
    recent_detections = []

    for analysis in analyses[:10]:
        recent_detections.append({
            "analysis_id": analysis.id,
            "type": analysis.analysis_type,
            "classification": analysis.classification,
            "confidence": analysis.confidence,
            "risk_score": analysis.risk_score,
            "severity": analysis.severity,
            "created_at": analysis.created_at,
        })

    return {
        "total_scans": total_scans,
        "total_threats": total_threats,

        "average_risk_score": round(
            average_risk_score,
            2
        ),

        "analysis_types": dict(
            type_counts
        ),

        "classifications": dict(
            classification_counts
        ),

        "severity_distribution": dict(
            severity_counts
        ),

        "recent_detections": recent_detections,
    }
