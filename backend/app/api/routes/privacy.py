from datetime import datetime
import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.db.database import get_db
from app.models.analysis import Analysis
from app.models.threat_indicator import ThreatIndicator
from app.models.privacy_preference import PrivacyPreference
from app.models.user import User
from app.services.privacy_service import delete_analyses, preference_for, purge_expired
from app.db.encrypted import encryption_ready

router = APIRouter(prefix="/api/privacy", tags=["Privacy and Trust Center"])


class PrivacyUpdate(BaseModel):
    no_save_default: bool = False
    retention_days: int | None = Field(default=None, ge=30, le=3650)


@router.get("/center")
def privacy_center(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    purge_expired(db, current_user.id)
    pref = preference_for(db, current_user.id)
    db.commit()
    saved_reports = db.query(Analysis).filter_by(user_id=current_user.id).count()
    stored_indicators = db.query(ThreatIndicator).join(Analysis).filter(Analysis.user_id == current_user.id).count()
    return {
        "preferences": {"no_save_default": pref.no_save_default, "retention_days": pref.retention_days},
        "my_data": {"saved_reports": saved_reports, "threat_indicators": stored_indicators},
        "processing": {"external_sharing": False, "uploads_persisted": False},
        "security": {
            "password_hashing": "bcrypt",
            "https_enforced": os.getenv("ENFORCE_HTTPS", "false").lower() == "true",
            "encryption_at_rest": encryption_ready() and os.getenv("DATA_ENCRYPTION_MIGRATION_COMPLETE", "false").lower() == "true",
            "encryption_status": "Encrypted; legacy rows migrated" if encryption_ready() and os.getenv("DATA_ENCRYPTION_MIGRATION_COMPLETE", "false").lower() == "true" else "Valid key or legacy-data migration is not confirmed",
            "encryption_key_location": "environment" if encryption_ready() else "not configured or invalid",
        },
        "retention": {"configured_days": pref.retention_days, "default": "Until you delete it" if not pref.retention_days else f"Automatically deleted after {pref.retention_days} days"},
        "updated_at": pref.updated_at,
    }


@router.put("/preferences")
def update_preferences(payload: PrivacyUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    pref = preference_for(db, current_user.id)
    pref.no_save_default = payload.no_save_default
    pref.retention_days = payload.retention_days
    pref.updated_at = datetime.utcnow()
    db.commit()
    return {"no_save_default": pref.no_save_default, "retention_days": pref.retention_days}


@router.delete("/analyses/{analysis_id}")
def delete_one(analysis_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    removed = delete_analyses(db, current_user.id, [analysis_id])
    if not removed:
        raise HTTPException(status_code=404, detail="Analysis not found")
    db.commit()
    return {"deleted": removed}


@router.delete("/my-data")
def delete_my_data(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    ids = [row.id for row in db.query(Analysis.id).filter_by(user_id=current_user.id).all()]
    removed = delete_analyses(db, current_user.id, ids)
    db.commit()
    return {"deleted_reports": removed, "message": "Your saved reports and linked threat data were deleted."}
