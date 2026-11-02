
import json

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    UploadFile,
    Request,
)
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.core.security import get_current_user

from app.models.user import User
from app.models.analysis import Analysis
from app.models.apk_analysis import APKAnalysis

from app.services.apk_analysis_service import analyze_and_save_apk
from app.services.privacy_service import no_save_response, should_save_report


router = APIRouter(
    prefix="/api/apk",
    tags=["APK Security"],
)

MAX_FILE_SIZE = 100 * 1024 * 1024


def parse_json_list(value: str | None):

    if not value:
        return []

    try:
        result = json.loads(value)
        return result if isinstance(result, list) else []

    except (json.JSONDecodeError, TypeError):
        return []


@router.post("/analyze")
async def analyze_apk_endpoint(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):

    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=415,
            detail="Please upload a valid .apk file.",
        )

    try:
        apk_bytes = await file.read(MAX_FILE_SIZE + 1)

        if not apk_bytes:
            raise HTTPException(
                status_code=400,
                detail="Uploaded APK is empty.",
            )

        if len(apk_bytes) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="APK exceeds the 100 MB upload limit.",
            )

        save_report = should_save_report(request, db, current_user.id)
        result = analyze_and_save_apk(
            apk_bytes=apk_bytes,
            file_name=file.filename,
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

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="APK analysis failed due to an internal error.",
        )

    finally:
        await file.close()


@router.get("/history")
def get_apk_history(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):

    limit = max(1, min(limit, 100))

    records = (
        db.query(Analysis, APKAnalysis)
        .join(
            APKAnalysis,
            APKAnalysis.analysis_id == Analysis.id,
        )
        .filter(
            Analysis.user_id == current_user.id,
            Analysis.analysis_type == "APK",
        )
        .order_by(Analysis.created_at.desc())
        .limit(limit)
        .all()
    )

    history = []

    for analysis, apk in records:
        history.append({
            "analysis_id": analysis.id,
            "file_name": apk.file_name,
            "file_hash": apk.file_hash,
            "package_name": apk.package_name,
            "version_name": apk.version_name,
            "version_code": apk.version_code,
            "file_size": apk.file_size,
            "classification": analysis.classification,
            "risk_score": analysis.risk_score,
            "severity": analysis.severity,
            "created_at": analysis.created_at,
        })

    return {
        "total": len(history),
        "history": history,
    }


@router.get("/{analysis_id}")
def get_apk_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):

    record = (
        db.query(Analysis, APKAnalysis)
        .join(
            APKAnalysis,
            APKAnalysis.analysis_id == Analysis.id,
        )
        .filter(
            Analysis.id == analysis_id,
            Analysis.user_id == current_user.id,
            Analysis.analysis_type == "APK",
        )
        .first()
    )

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="APK analysis not found.",
        )

    analysis, apk = record

    return {
        "analysis_id": analysis.id,
        "file_name": apk.file_name,
        "file_hash": apk.file_hash,
        "file_size": apk.file_size,
        "package_name": apk.package_name,
        "version_name": apk.version_name,
        "version_code": apk.version_code,
        "permissions": parse_json_list(apk.permissions),
        "suspicious_apis": parse_json_list(apk.suspicious_apis),
        "extracted_urls": parse_json_list(apk.extracted_urls),
        "classification": analysis.classification,
        "confidence": analysis.confidence,
        "risk_score": analysis.risk_score,
        "severity": analysis.severity,
        "explanation": analysis.explanation,
        "recommendation": analysis.recommendation,
        "created_at": analysis.created_at,
    }
