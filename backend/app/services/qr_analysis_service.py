
import json

from sqlalchemy.orm import Session
from urllib.parse import urlsplit

from app.ml.qr_security.qr_decoder import decode_qr_image
from app.ml.url_detection.url_predictor import predict_url

from app.services.risk_engine import calculate_url_risk
from app.services.threat_intelligence_service import add_indicator

from app.models.analysis import Analysis
from app.models.qr_analysis import QRAnalysis


def analyze_qr(
    image_bytes: bytes,
    db: Session,
    user_id: int,
    save_report: bool = True,
) -> dict:
    """
    Decode a QR image, analyze extracted URLs using the shared
    URL detection and risk engine, and save the result.
    """

    try:
        # 1. Decode QR image
        decoded_result = decode_qr_image(image_bytes)
        payloads = decoded_result["payloads"]

        # 2. Extract URLs
        urls = [
            item["decoded_url"]
            for item in payloads
            if item["payload_type"] == "URL"
            and item.get("decoded_url")
        ]

        url_results = []

        # 3. Analyze each URL using the shared URL pipeline
        for url in urls:

            prediction = predict_url(url)

            risk = calculate_url_risk(
                phishing_probability=prediction["phishing_probability"],
                classification=prediction["classification"],
                features=prediction["features"],
            )

            url_results.append({
                "url": prediction["url"],
                "classification": risk["classification"],
                "ml_classification": risk["ml_classification"],
                "phishing_probability": prediction["phishing_probability"],
                "legitimate_probability": prediction["legitimate_probability"],
                "confidence": prediction["confidence"],
                "risk_score": risk["risk_score"],
                "severity": risk["severity"],
                "explanation": risk["explanation"],
                "indicators": risk["indicators"],
                "recommendation": risk["recommendation"],
                "domain_reputation": risk["domain_reputation"],
            })

        # 4. Calculate overall QR risk
        if url_results:

            highest_risk = max(
                url_results,
                key=lambda item: item["risk_score"],
            )

            classification = highest_risk["classification"]
            confidence = highest_risk["confidence"]
            risk_score = highest_risk["risk_score"]
            severity = highest_risk["severity"]

            explanation = (
                f"QR code contains {len(urls)} URL(s). "
                f"Overall classification is based on the highest-risk URL. "
                f"{highest_risk['explanation']}"
            )

            recommendation = highest_risk["recommendation"]

        else:
            # Non-URL payloads have not undergone URL-based analysis.
            classification = "NON_URL"
            confidence = None
            risk_score = 0
            severity = "INFO"

            explanation = (
                "QR code decoded successfully, but no URL was found. "
                "URL-based phishing analysis was not performed."
            )

            recommendation = (
                "Verify the QR code's source and understand its content "
                "before using it."
            )

        if save_report:
            # 5. Create parent analysis record
            analysis = Analysis(
                user_id=user_id,
                analysis_type="QR",
                status="COMPLETED",
                classification=classification,
                confidence=confidence,
                risk_score=risk_score,
                severity=severity,
                explanation=explanation,
                recommendation=recommendation,
            )
            db.add(analysis)
            db.flush()

            payload_type = (
                payloads[0]["payload_type"]
                if len(payloads) == 1 else "MULTIPLE"
            )
            qr_record = QRAnalysis(
                analysis_id=analysis.id,
                payload=json.dumps(payloads),
                payload_type=payload_type,
                decoded_url=urls[0] if urls else None,
                image_path=None,
            )
            db.add(qr_record)

            for item in url_results:
                if item["classification"] == "PHISHING":
                    add_indicator(db=db, analysis_id=analysis.id,
                                  indicator_type="URL", indicator_value=item["url"],
                                  source="QR_ANALYSIS")
                    domain = urlsplit(item["url"]).hostname
                    if domain:
                        add_indicator(db=db, analysis_id=analysis.id,
                                      indicator_type="DOMAIN", indicator_value=domain,
                                      source="QR_ANALYSIS")
            db.commit()

        return {
            "analysis_id": analysis.id if save_report else None,
            "decoded": True,
            "payload_count": len(payloads),
            "payloads": payloads,
            "classification": classification,
            "confidence": confidence,
            "risk_score": risk_score,
            "severity": severity,
            "explanation": explanation,
            "recommendation": recommendation,
            "url_results": url_results,
        }

    except Exception:
        db.rollback()
        raise
