# QR routes will be implemented in Phase 4.

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
from app.models.qr_analysis import QRAnalysis

from app.services.qr_analysis_service import analyze_qr
from app.services.privacy_service import no_save_response, should_save_report


router = APIRouter(
    prefix="/api/qr",
    tags=["QR Security"],
)

MAX_FILE_SIZE = 5 * 1024 * 1024

ALLOWED_CONTENT_TYPES = {
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/bmp",
}


def parse_payload(payload: str | None):
    if not payload:
        return []

    try:
        return json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return []


@router.post("/analyze")
async def analyze_qr_endpoint(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Upload and analyze a QR code image.
    """

    if file.content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(
            status_code=415,
            detail="Unsupported image format. Upload PNG, JPEG, WEBP or BMP.",
        )

    try:
        image_bytes = await file.read(MAX_FILE_SIZE + 1)

        if not image_bytes:
            raise HTTPException(
                status_code=400,
                detail="Uploaded image is empty.",
            )

        if len(image_bytes) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="Image size exceeds the 5 MB limit.",
            )

        save_report = should_save_report(request, db, current_user.id)
        result = analyze_qr(
            image_bytes=image_bytes,
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
        raise HTTPException(
            status_code=503,
            detail=str(error),
        )

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="QR analysis failed due to an internal error.",
        )

    finally:
        await file.close()


@router.get("/history")
def get_qr_history(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Return QR analysis history for the authenticated user.
    """

    limit = max(1, min(limit, 100))

    records = (
        db.query(Analysis, QRAnalysis)
        .join(
            QRAnalysis,
            QRAnalysis.analysis_id == Analysis.id,
        )
        .filter(
            Analysis.user_id == current_user.id,
            Analysis.analysis_type == "QR",
        )
        .order_by(Analysis.created_at.desc())
        .limit(limit)
        .all()
    )

    history = []

    for analysis, qr_record in records:
        history.append({
            "analysis_id": analysis.id,
            "payload_type": qr_record.payload_type,
            "payloads": parse_payload(qr_record.payload),
            "decoded_url": qr_record.decoded_url,
            "classification": analysis.classification,
            "confidence": analysis.confidence,
            "risk_score": analysis.risk_score,
            "severity": analysis.severity,
            "created_at": analysis.created_at,
        })

    return {
        "total": len(history),
        "history": history,
    }


@router.get("/{analysis_id}")
def get_qr_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Return details of one QR analysis belonging to the user.
    """

    record = (
        db.query(Analysis, QRAnalysis)
        .join(
            QRAnalysis,
            QRAnalysis.analysis_id == Analysis.id,
        )
        .filter(
            Analysis.id == analysis_id,
            Analysis.user_id == current_user.id,
            Analysis.analysis_type == "QR",
        )
        .first()
    )

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="QR analysis not found.",
        )

    analysis, qr_record = record

    return {
        "analysis_id": analysis.id,
        "payload_type": qr_record.payload_type,
        "payloads": parse_payload(qr_record.payload),
        "decoded_url": qr_record.decoded_url,
        "classification": analysis.classification,
        "confidence": analysis.confidence,
        "risk_score": analysis.risk_score,
        "severity": analysis.severity,
        "explanation": analysis.explanation,
        "recommendation": analysis.recommendation,
        "created_at": analysis.created_at,
    }
