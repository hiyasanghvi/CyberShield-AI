
from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    UploadFile,
    Form,
    Request,
)
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.analysis import Analysis

from app.services.screenshot_analysis_service import analyze_screenshot
from app.services.payment_scam_service import analyze_payment_message
from app.services.privacy_service import no_save_response, should_save_report


router = APIRouter(
    prefix="/api/safety",
    tags=["Screenshot and Payment Safety"],
)

MAX_IMAGE_SIZE = 10 * 1024 * 1024

ALLOWED_TYPES = {
    "image/jpeg",
    "image/png",
    "image/webp",
}


def save_analysis(db: Session, user_id: int, result: dict, analysis_type: str):
    try:
        record = Analysis(
            user_id=user_id,
            analysis_type=analysis_type,
            status="COMPLETED",
            classification=result["classification"],
            confidence=None,
            risk_score=result["risk_score"],
            severity=result["severity"],
            explanation=result["explanation"],
            recommendation=" ".join(result["recommended_actions"]),
        )

        db.add(record)
        db.commit()
        db.refresh(record)

        result["analysis_id"] = record.id
        return result

    except Exception:
        db.rollback()
        raise


@router.post("/screenshot/analyze")
async def analyze_screenshot_endpoint(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=415,
            detail="Upload a JPG, PNG or WEBP image.",
        )

    try:
        image_bytes = await file.read(MAX_IMAGE_SIZE + 1)

        if len(image_bytes) > MAX_IMAGE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="Image exceeds the 10 MB limit.",
            )

        result = analyze_screenshot(
            image_bytes=image_bytes,
            file_name=file.filename or "uploaded_image",
        )

        if should_save_report(request, db, current_user.id):
            return save_analysis(db, current_user.id, result, "SCREENSHOT")
        return no_save_response(result)

    except HTTPException:
        raise

    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

    except RuntimeError as error:
        raise HTTPException(status_code=500, detail=str(error))

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Screenshot analysis failed.",
        )

    finally:
        await file.close()


@router.post("/payment/analyze")
def analyze_payment_text_endpoint(
    request: Request,
    message: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        result = analyze_payment_message(message)

        if should_save_report(request, db, current_user.id):
            return save_analysis(db, current_user.id, result, "PAYMENT")
        return no_save_response(result)

    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Payment message analysis failed.",
        )
