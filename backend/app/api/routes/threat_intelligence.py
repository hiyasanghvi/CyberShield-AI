# Threat intelligence routes will be implemented in Phase 8.
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.threat_indicator import ThreatIndicator
from app.models.analysis import Analysis
from app.core.security import get_current_user
from app.services.threat_intelligence_service import (
    get_analysis_indicators,
)

router = APIRouter(
    prefix="/api/threat-intelligence",
    tags=["Threat Intelligence"],
)


@router.get("/indicators")
def get_indicators(
    indicator_type: str | None = Query(default=None),
    search: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = (
        db.query(ThreatIndicator)
        .join(
            Analysis,
            ThreatIndicator.analysis_id == Analysis.id,
        )
        .filter(
            Analysis.user_id == current_user.id
        )
    )

    if indicator_type:
        query = query.filter(
            ThreatIndicator.indicator_type
            == indicator_type.upper()
        )

    indicators = (
        query
        .order_by(ThreatIndicator.created_at.desc())
        .limit(limit)
        .all()
    )
    if search:
        needle = search.casefold()
        indicators = [item for item in indicators if needle in item.indicator_value.casefold()]

    return {
        "total": len(indicators),
        "indicators": [
            {
                "id": item.id,
                "analysis_id": item.analysis_id,
                "type": item.indicator_type,
                "value": item.indicator_value,
                "source": item.source,
                "created_at": item.created_at,
            }
            for item in indicators
        ],
    }


@router.get("/analysis/{analysis_id}")
def analysis_indicators(
    analysis_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    analysis = (
        db.query(Analysis)
        .filter(
            Analysis.id == analysis_id,
            Analysis.user_id == current_user.id,
        )
        .first()
    )

    if not analysis:
        return {
            "analysis_id": analysis_id,
            "total": 0,
            "indicators": [],
        }

    indicators = get_analysis_indicators(
        db,
        analysis_id,
    )

    return {
        "analysis_id": analysis_id,
        "total": len(indicators),
        "indicators": indicators,
    }
