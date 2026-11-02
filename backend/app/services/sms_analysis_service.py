import re
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.ml.text_detection.sms_predictor import predict_sms
from app.services.sms_risk_engine import calculate_sms_risk
from app.services.threat_intelligence_service import add_indicator
from app.models.analysis import Analysis
from app.models.text_analysis import TextAnalysis


def analyze_sms(
    text: str,
    db: Session | None = None,
    user_id: int | None = None,
    save_report: bool = True,
) -> dict:

    prediction = predict_sms(text)

    risk = calculate_sms_risk(
        spam_probability=prediction["spam_probability"],
        classification=prediction["classification"],
        text=text,
    )

    result = {
        "text": text,
        "classification": prediction["classification"],
        "spam_probability": prediction["spam_probability"],
        "ham_probability": prediction["ham_probability"],
        "confidence": prediction["confidence"],
        "risk_score": risk["risk_score"],
        "severity": risk["severity"],
        "explanation": risk["explanation"],
        "indicators": risk["indicators"],
        "recommendation": risk["recommendation"],
    }

    if db is not None and user_id is not None and save_report:

        analysis = Analysis(
            user_id=user_id,
            analysis_type="SMS",
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

        lower_text = text.lower()

        # Extract URLs
        urls = re.findall(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', text, re.I)
        urls = [url.rstrip(".,!?;:)") for url in urls]

        # Extract phone numbers (basic pattern)
        phones = re.findall(r'(?<!\w)(?:\+?\d[\d\s-]{8,}\d)(?!\w)', text)

        is_spam = prediction["classification"] == "SPAM"

        if is_spam:
            add_indicator(
                db, analysis.id, "SMS", text[:500], "SMS_ANALYSIS"
            )

            for url in urls:
                normalized_url = url if url.startswith(("http://", "https://")) else f"http://{url}"

                add_indicator(
                    db, analysis.id, "URL", normalized_url, "SMS_ANALYSIS"
                )

                domain = urlsplit(normalized_url).hostname
                if domain:
                    add_indicator(
                        db, analysis.id, "DOMAIN", domain, "SMS_ANALYSIS"
                    )

            for phone in phones:
                cleaned_phone = re.sub(r"[\s-]", "", phone)
                add_indicator(
                    db, analysis.id, "PHONE", cleaned_phone, "SMS_ANALYSIS"
                )

        text_analysis = TextAnalysis(
            analysis_id=analysis.id,
            text_content=text,
            language=None,
            contains_url=bool(urls),
            contains_phone=bool(phones),
            contains_money_indicator=any(
                word in lower_text
                for word in [
                    "cash", "money", "reward", "prize",
                    "payment", "refund", "bonus",
                ]
            ),
            contains_urgency=any(
                word in lower_text
                for word in [
                    "urgent", "immediately", "act now",
                    "hurry", "expires", "last chance",
                ]
            ),
        )

        db.add(text_analysis)
        db.commit()

        result["analysis_id"] = analysis.id

    return result
