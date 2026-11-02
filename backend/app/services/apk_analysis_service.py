
import json

from sqlalchemy.orm import Session

from app.ml.apk_analysis.apk_analyzer import analyze_apk_file
from app.models.analysis import Analysis
from app.models.apk_analysis import APKAnalysis


def analyze_and_save_apk(
    apk_bytes: bytes,
    file_name: str,
    db: Session,
    user_id: int,
    save_report: bool = True,
) -> dict:

    result = analyze_apk_file(
        apk_bytes=apk_bytes,
        file_name=file_name,
    )

    try:
        if not save_report:
            return result

        analysis = Analysis(
            user_id=user_id,
            analysis_type="APK",
            status="COMPLETED",
            classification=result["classification"],
            confidence=result["confidence"],
            risk_score=result["risk_score"],
            severity=result["severity"],
            explanation=result["explanation"],
            recommendation=result["recommendation"],
        )

        db.add(analysis)
        db.flush()

        apk_record = APKAnalysis(
            analysis_id=analysis.id,
            file_name=result["file_name"],
            file_hash=result["file_hash"],
            package_name=result["package_name"],
            version_name=result["version_name"],
            version_code=result["version_code"],
            permissions=json.dumps(result["permissions"]),
            suspicious_apis=json.dumps(result["suspicious_apis"]),
            extracted_urls=json.dumps(result["extracted_urls"]),
            file_size=result["file_size"],
        )

        db.add(apk_record)
        db.commit()

        result["analysis_id"] = analysis.id

        return result

    except Exception:
        db.rollback()
        raise
