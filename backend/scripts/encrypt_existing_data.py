"""One-time encryption of legacy plaintext analysis columns (run after SQL migration)."""
from app.db.database import SessionLocal
from app.models.analysis import Analysis
from app.models.url_analysis import URLAnalysis
from app.models.text_analysis import TextAnalysis
from app.models.email_analysis import EmailAnalysis
from app.models.qr_analysis import QRAnalysis
from app.models.apk_analysis import APKAnalysis
from app.models.network_analysis import NetworkAnalysis
from app.models.threat_indicator import ThreatIndicator

FIELDS = {
    Analysis: ("explanation", "recommendation"),
    URLAnalysis: ("url", "domain"),
    TextAnalysis: ("text_content",),
    EmailAnalysis: ("sender_email", "subject", "body", "header_data"),
    QRAnalysis: ("payload", "decoded_url"),
    APKAnalysis: ("file_name", "file_hash", "permissions", "suspicious_apis", "extracted_urls"),
    NetworkAnalysis: ("source_ip", "destination_ip"),
    ThreatIndicator: ("indicator_value",),
}

db = SessionLocal()
try:
    for model, names in FIELDS.items():
        for row in db.query(model).yield_per(100):
            for name in names:
                value = getattr(row, name)
                if value is not None:
                    setattr(row, name, value)
    db.commit()
    print("Legacy analysis fields encrypted successfully.")
except Exception:
    db.rollback()
    raise
finally:
    db.close()
