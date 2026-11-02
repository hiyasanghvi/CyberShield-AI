from sqlalchemy.orm import Session

from app.models.analysis import Analysis
from app.models.threat_indicator import ThreatIndicator
from app.models.threat_relationship import ThreatRelationship


def normalize_indicator(value: str) -> str:
    """Normalize values for reliable exact matching."""
    return value.strip().lower().rstrip("/")


def create_correlations_for_indicator(
    db: Session,
    indicator: ThreatIndicator,
) -> int:
    """
    Find matching indicators from other analyses of the same user
    and create relationships without duplicating existing links.
    """
    analysis = (
        db.query(Analysis)
        .filter(Analysis.id == indicator.analysis_id)
        .first()
    )

    if not analysis:
        return 0

    normalized_value = normalize_indicator(
        indicator.indicator_value
    )

    if not normalized_value:
        return 0

    candidates = (
        db.query(ThreatIndicator)
        .join(
            Analysis,
            ThreatIndicator.analysis_id == Analysis.id,
        )
        .filter(
            Analysis.user_id == analysis.user_id,
            ThreatIndicator.indicator_type
            == indicator.indicator_type,
            ThreatIndicator.id != indicator.id,
        )
        .all()
    )

    created_count = 0

    for candidate in candidates:
        if normalize_indicator(candidate.indicator_value) != normalized_value:
            continue

        # Do not correlate indicators from the same analysis.
        if candidate.analysis_id == indicator.analysis_id:
            continue

        existing = (
            db.query(ThreatRelationship)
            .filter(
                (
                    (
                        ThreatRelationship.source_indicator_id
                        == candidate.id
                    )
                    & (
                        ThreatRelationship.target_indicator_id
                        == indicator.id
                    )
                )
                |
                (
                    (
                        ThreatRelationship.source_indicator_id
                        == indicator.id
                    )
                    & (
                        ThreatRelationship.target_indicator_id
                        == candidate.id
                    )
                )
            )
            .first()
        )

        if existing:
            continue

        relationship = ThreatRelationship(
            source_indicator_id=candidate.id,
            target_indicator_id=indicator.id,
            relationship_type="SAME_INDICATOR",
        )

        db.add(relationship)
        created_count += 1

    if created_count:
        db.flush()

    return created_count


def add_indicator(
    db: Session,
    analysis_id: int,
    indicator_type: str,
    indicator_value: str,
    source: str,
):
    if not indicator_value or not indicator_value.strip():
        return None

    indicator_type = indicator_type.strip().upper()
    indicator_value = indicator_value.strip()

    existing = next((item for item in db.query(ThreatIndicator).filter(
        ThreatIndicator.analysis_id == analysis_id,
        ThreatIndicator.indicator_type == indicator_type,
    ).all() if item.indicator_value == indicator_value), None)

    if existing:
        create_correlations_for_indicator(db, existing)
        return existing

    indicator = ThreatIndicator(
        analysis_id=analysis_id,
        indicator_type=indicator_type,
        indicator_value=indicator_value,
        source=source,
    )

    db.add(indicator)
    db.flush()

    create_correlations_for_indicator(db, indicator)

    return indicator


def get_analysis_indicators(
    db: Session,
    analysis_id: int,
):
    indicators = (
        db.query(ThreatIndicator)
        .filter(
            ThreatIndicator.analysis_id == analysis_id
        )
        .order_by(ThreatIndicator.created_at.desc())
        .all()
    )

    return [
        {
            "id": indicator.id,
            "type": indicator.indicator_type,
            "value": indicator.indicator_value,
            "source": indicator.source,
            "created_at": indicator.created_at,
        }
        for indicator in indicators
    ]
