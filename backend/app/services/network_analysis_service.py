
from sqlalchemy.orm import Session

from app.ml.network_security.network_analyzer import (
    analyze_network_capture,
)
from app.models.analysis import Analysis
from app.models.network_analysis import NetworkAnalysis


def analyze_and_save_network(
    file_bytes: bytes,
    file_name: str,
    db: Session,
    user_id: int,
    save_report: bool = True,
) -> dict:

    result = analyze_network_capture(
        file_bytes=file_bytes,
        file_name=file_name,
    )

    try:
        if not save_report:
            return result

        analysis = Analysis(
            user_id=user_id,
            analysis_type="NETWORK",
            status="COMPLETED",
            classification=result["classification"],
            confidence=None,
            risk_score=result["risk_score"],
            severity=result["severity"],
            explanation=result["explanation"],
            recommendation=result["recommendation"],
        )

        db.add(analysis)
        db.flush()

        flow = result.get("largest_flow") or {}

        network_record = NetworkAnalysis(
            analysis_id=analysis.id,
            source_ip=flow.get("source_ip"),
            destination_ip=flow.get("destination_ip"),
            protocol=flow.get("protocol"),
            source_port=flow.get("source_port"),
            destination_port=flow.get("destination_port"),
            duration=flow.get("duration", result["duration"]),
            total_bytes=result["total_bytes"],
            total_packets=result["total_packets"],
            flow_rate=result["flow_rate"],
            attack_category=result["attack_category"],
        )

        db.add(network_record)
        db.commit()

        result["analysis_id"] = analysis.id
        return result

    except Exception:
        db.rollback()
        raise
