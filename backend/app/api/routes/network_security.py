
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
from app.models.network_analysis import NetworkAnalysis

from app.services.network_analysis_service import (
    analyze_and_save_network,
)
from app.services.privacy_service import no_save_response, should_save_report


router = APIRouter(
    prefix="/api/network",
    tags=["Network Security"],
)

MAX_FILE_SIZE = 50 * 1024 * 1024

ALLOWED_EXTENSIONS = (".pcap", ".pcapng")


@router.post("/analyze")
async def analyze_network_endpoint(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):

    filename = file.filename or ""

    if not filename.lower().endswith(ALLOWED_EXTENSIONS):
        raise HTTPException(
            status_code=415,
            detail="Upload a .pcap or .pcapng file.",
        )

    try:
        file_bytes = await file.read(MAX_FILE_SIZE + 1)

        if not file_bytes:
            raise HTTPException(
                status_code=400,
                detail="Uploaded capture file is empty.",
            )

        if len(file_bytes) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="Capture file exceeds the 50 MB limit.",
            )

        save_report = should_save_report(request, db, current_user.id)
        result = analyze_and_save_network(
            file_bytes=file_bytes,
            file_name=filename,
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
            detail="Network analysis failed due to an internal error.",
        )

    finally:
        await file.close()


@router.get("/history")
def get_network_history(
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):

    limit = max(1, min(limit, 100))

    records = (
        db.query(Analysis, NetworkAnalysis)
        .join(
            NetworkAnalysis,
            NetworkAnalysis.analysis_id == Analysis.id,
        )
        .filter(
            Analysis.user_id == current_user.id,
            Analysis.analysis_type == "NETWORK",
        )
        .order_by(Analysis.created_at.desc())
        .limit(limit)
        .all()
    )

    history = []

    for analysis, network in records:
        history.append({
            "analysis_id": analysis.id,
            "source_ip": network.source_ip,
            "destination_ip": network.destination_ip,
            "protocol": network.protocol,
            "attack_category": network.attack_category,
            "total_packets": network.total_packets,
            "total_bytes": network.total_bytes,
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
def get_network_analysis(
    analysis_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):

    record = (
        db.query(Analysis, NetworkAnalysis)
        .join(
            NetworkAnalysis,
            NetworkAnalysis.analysis_id == Analysis.id,
        )
        .filter(
            Analysis.id == analysis_id,
            Analysis.user_id == current_user.id,
            Analysis.analysis_type == "NETWORK",
        )
        .first()
    )

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Network analysis not found.",
        )

    analysis, network = record

    return {
        "analysis_id": analysis.id,
        "source_ip": network.source_ip,
        "destination_ip": network.destination_ip,
        "protocol": network.protocol,
        "source_port": network.source_port,
        "destination_port": network.destination_port,
        "duration": network.duration,
        "total_bytes": network.total_bytes,
        "total_packets": network.total_packets,
        "flow_rate": network.flow_rate,
        "attack_category": network.attack_category,
        "classification": analysis.classification,
        "confidence": analysis.confidence,
        "risk_score": analysis.risk_score,
        "severity": analysis.severity,
        "explanation": analysis.explanation,
        "recommendation": analysis.recommendation,
        "created_at": analysis.created_at,
    }
