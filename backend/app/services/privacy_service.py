from datetime import datetime, timedelta
import os

from sqlalchemy.orm import Session
from fastapi import HTTPException

from app.models.analysis import Analysis
from app.models.threat_indicator import ThreatIndicator
from app.models.threat_relationship import ThreatRelationship
from app.models.privacy_preference import PrivacyPreference
from app.models.url_analysis import URLAnalysis
from app.models.text_analysis import TextAnalysis
from app.models.email_analysis import EmailAnalysis
from app.models.qr_analysis import QRAnalysis
from app.models.apk_analysis import APKAnalysis
from app.models.network_analysis import NetworkAnalysis
from app.db.encrypted import encryption_ready


SUBTYPE_MODELS = (URLAnalysis, TextAnalysis, EmailAnalysis, QRAnalysis, APKAnalysis, NetworkAnalysis)


def should_save_report(request, db: Session, user_id: int) -> bool:
    value = request.headers.get("x-save-report")
    save = value.lower() in {"true", "1", "yes"} if value is not None else not preference_for(db, user_id).no_save_default
    if save and (not encryption_ready() or os.getenv("DATA_ENCRYPTION_MIGRATION_COMPLETE", "false").lower() != "true"):
        raise HTTPException(status_code=503, detail="Saved reports are paused until the encryption key and database migration are configured. Choose no-save mode or contact the administrator.")
    return save


SENSITIVE_RESULT_KEYS = {
    "url", "text", "sender_email", "subject", "body", "input", "payload",
    "payloads", "decoded_url", "extracted_text", "file_name", "file_hash",
    "permissions", "suspicious_apis", "extracted_urls", "source_ip",
    "destination_ip", "source_port", "destination_port", "indicators",
    "domain", "package_name", "version_name", "version_code",
    "domain_reputation", "largest_flow", "flows", "evidence", "dns_queries",
}


def no_save_response(result: dict) -> dict:
    """Keep result metadata but do not echo raw or directly identifying input."""
    def scrub(value):
        if isinstance(value, dict):
            return {key: scrub(item) for key, item in value.items() if key not in SENSITIVE_RESULT_KEYS}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        return value

    cleaned = scrub(result)
    cleaned["analysis_id"] = None
    cleaned["saved_report"] = False
    return cleaned


def preference_for(db: Session, user_id: int) -> PrivacyPreference:
    pref = db.query(PrivacyPreference).filter_by(user_id=user_id).first()
    if pref is None:
        pref = PrivacyPreference(user_id=user_id, no_save_default=False, retention_days=None)
        db.add(pref)
        db.flush()
    return pref


def delete_analyses(db: Session, user_id: int, analysis_ids: list[int]) -> int:
    records = db.query(Analysis.id).filter(
        Analysis.user_id == user_id, Analysis.id.in_(analysis_ids)
    ).all() if analysis_ids else []
    ids = [record[0] for record in records]
    if not ids:
        return 0

    indicators = db.query(ThreatIndicator.id).filter(ThreatIndicator.analysis_id.in_(ids)).all()
    indicator_ids = [indicator[0] for indicator in indicators]
    if indicator_ids:
        db.query(ThreatRelationship).filter(
            (ThreatRelationship.source_indicator_id.in_(indicator_ids)) |
            (ThreatRelationship.target_indicator_id.in_(indicator_ids))
        ).delete(synchronize_session=False)
        db.query(ThreatIndicator).filter(ThreatIndicator.id.in_(indicator_ids)).delete(synchronize_session=False)

    # Remove any legacy persisted upload paths only when they are inside the configured upload root.
    upload_root = os.path.realpath(os.getenv("UPLOAD_DIR", "uploads"))
    for (path,) in db.query(QRAnalysis.image_path).filter(QRAnalysis.analysis_id.in_(ids)).all():
        if path:
            real_path = os.path.realpath(path)
            try:
                is_managed_upload = os.path.commonpath([upload_root, real_path]) == upload_root
            except ValueError:
                is_managed_upload = False
            if is_managed_upload and os.path.isfile(real_path):
                os.remove(real_path)

    for model in SUBTYPE_MODELS:
        db.query(model).filter(model.analysis_id.in_(ids)).delete(synchronize_session=False)

    db.query(Analysis).filter(Analysis.id.in_(ids)).delete(synchronize_session=False)
    return len(ids)


def purge_expired(db: Session, user_id: int) -> int:
    pref = db.query(PrivacyPreference).filter_by(user_id=user_id).first()
    if not pref or not pref.retention_days:
        return 0
    cutoff = datetime.utcnow() - timedelta(days=pref.retention_days)
    ids = [row.id for row in db.query(Analysis.id).filter(
        Analysis.user_id == user_id, Analysis.created_at < cutoff
    ).all()]
    removed = delete_analyses(db, user_id, ids)
    if removed:
        db.commit()
    return removed
