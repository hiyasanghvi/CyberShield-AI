from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session, aliased

from app.db.database import get_db
from app.models.threat_indicator import ThreatIndicator
from app.models.threat_relationship import ThreatRelationship
from app.models.analysis import Analysis
from app.core.security import get_current_user


router = APIRouter(
    prefix="/api/correlation",
    tags=["Threat Correlation"],
)


@router.get("")
def get_correlations(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    SourceIndicator = aliased(ThreatIndicator)
    TargetIndicator = aliased(ThreatIndicator)

    SourceAnalysis = aliased(Analysis)
    TargetAnalysis = aliased(Analysis)

    relationships = (
        db.query(
            ThreatRelationship,
            SourceIndicator,
            TargetIndicator,
        )
        .join(
            SourceIndicator,
            ThreatRelationship.source_indicator_id
            == SourceIndicator.id,
        )
        .join(
            TargetIndicator,
            ThreatRelationship.target_indicator_id
            == TargetIndicator.id,
        )
        .join(
            SourceAnalysis,
            SourceIndicator.analysis_id == SourceAnalysis.id,
        )
        .join(
            TargetAnalysis,
            TargetIndicator.analysis_id == TargetAnalysis.id,
        )
        .filter(
            SourceAnalysis.user_id == current_user.id,
            TargetAnalysis.user_id == current_user.id,
        )
        .order_by(
            ThreatRelationship.created_at.desc()
        )
        .all()
    )

    result = []

    for relationship, source, target in relationships:
        result.append({
            "relationship_id": relationship.id,
            "source": {
                "id": source.id,
                "analysis_id": source.analysis_id,
                "type": source.indicator_type,
                "value": source.indicator_value,
            },
            "target": {
                "id": target.id,
                "analysis_id": target.analysis_id,
                "type": target.indicator_type,
                "value": target.indicator_value,
            },
            "relationship_type": relationship.relationship_type,
            "created_at": relationship.created_at,
        })

    return {
        "total": len(result),
        "relationships": result,
    }