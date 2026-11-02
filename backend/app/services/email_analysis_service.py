import re
from urllib.parse import urlsplit

from app.ml.text_detection.email_predictor import predict_email
from app.services.email_risk_engine import calculate_email_risk
from app.models.analysis import Analysis
from app.models.email_analysis import EmailAnalysis
from app.services.threat_intelligence_service import add_indicator


def analyze_email(
    sender_email=None,
    subject="",
    body="",
    has_attachment=False,
    header_data=None,
    db=None,
    user_id=None,
    save_report=True,
):
    prediction = predict_email(subject=subject, body=body)

    risk = calculate_email_risk(
        spam_probability=prediction["spam_probability"],
        subject=subject,
        body=body,
        contains_url=prediction["contains_url"],
        url_count=prediction["url_count"],
        has_attachment=has_attachment,
    )

    analysis_id = None

    if db is not None and user_id is not None and save_report:

        analysis = Analysis(
            user_id=user_id,
            analysis_type="EMAIL",
            status="COMPLETED",
            classification=risk["classification"],
            confidence=prediction["confidence"],
            risk_score=risk["risk_score"],
            severity=risk["severity"],
            explanation=risk["explanation"],
            recommendation=risk["recommendation"],
        )

        db.add(analysis)
        db.flush()

        email_record = EmailAnalysis(
            analysis_id=analysis.id,
            sender_email=sender_email,
            subject=subject,
            body=body,
            contains_url=prediction["contains_url"],
            url_count=prediction["url_count"],
            has_attachment=has_attachment,
            header_data=header_data,
        )

        db.add(email_record)

        # Extract actual URLs from email content
        combined_text = f"{subject}\n{body}"

        urls = re.findall(
            r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
            combined_text,
            re.I,
        )
        urls = list(dict.fromkeys(url.rstrip(".,!?;:)") for url in urls))

        if risk["classification"] == "SPAM":

            if sender_email:
                add_indicator(
                    db=db,
                    analysis_id=analysis.id,
                    indicator_type="EMAIL",
                    indicator_value=sender_email,
                    source="EMAIL_ANALYSIS",
                )

            for url in urls:
                normalized_url = (
                    url if url.startswith(("http://", "https://"))
                    else f"http://{url}"
                )

                add_indicator(
                    db=db,
                    analysis_id=analysis.id,
                    indicator_type="URL",
                    indicator_value=normalized_url,
                    source="EMAIL_ANALYSIS",
                )

                domain = urlsplit(normalized_url).hostname

                if domain:
                    add_indicator(
                        db=db,
                        analysis_id=analysis.id,
                        indicator_type="DOMAIN",
                        indicator_value=domain,
                        source="EMAIL_ANALYSIS",
                    )

        db.commit()
        db.refresh(analysis)
        analysis_id = analysis.id

    return {
        "analysis_id": analysis_id,
        "sender_email": sender_email,
        "subject": subject,
        "classification": risk["classification"],
        "spam_probability": prediction["spam_probability"],
        "ham_probability": prediction["ham_probability"],
        "confidence": prediction["confidence"],
        "risk_score": risk["risk_score"],
        "severity": risk["severity"],
        "explanation": risk["explanation"],
        "indicators": risk["indicators"],
        "recommendation": risk["recommendation"],
        "contains_url": prediction["contains_url"],
        "url_count": prediction["url_count"],
        "has_attachment": has_attachment,
    }
