
from sqlalchemy.orm import Session

from app.ml.url_detection.url_predictor import predict_url
from app.services.risk_engine import calculate_url_risk
from app.models.analysis import Analysis
from app.models.url_analysis import URLAnalysis
from app.services.threat_intelligence_service import add_indicator


def analyze_url(
    url: str,
    db: Session | None = None,
    user_id: int | None = None,
    save_report: bool = True,
) -> dict:

    # 1. ML prediction
    prediction = predict_url(url)

    # 2. Combined risk assessment
    risk = calculate_url_risk(
        phishing_probability=prediction["phishing_probability"],
        classification=prediction["classification"],
        features=prediction["features"],
    )

    # 3. Final result
    result = {
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
    }

    # 4. Save to database
    if db is not None and user_id is not None and save_report:

        analysis = Analysis(
            user_id=user_id,
            analysis_type="URL",
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

        features = prediction["features"]

        url_analysis = URLAnalysis(
            analysis_id=analysis.id,
            url=result["url"],
            domain=features.get("Domain"),
            https_enabled=features.get("IsHTTPS"),
            url_length=features.get("URLLength"),
            domain_length=features.get("DomainLength"),
            num_subdomains=features.get("NoOfSubDomain"),
            has_ip_address=features.get("IsDomainIP"),
            has_suspicious_keyword=None,
        )

        db.add(url_analysis)

        # Store threat indicators only when the final assessment
        # still classifies the URL as phishing.
        if result["classification"] == "PHISHING":

            add_indicator(
                db=db,
                analysis_id=analysis.id,
                indicator_type="URL",
                indicator_value=result["url"],
                source="URL_ANALYSIS",
            )

            domain = features.get("Domain")

            if domain:
                add_indicator(
                    db=db,
                    analysis_id=analysis.id,
                    indicator_type="DOMAIN",
                    indicator_value=domain,
                    source="URL_ANALYSIS",
                )

        db.commit()
        result["analysis_id"] = analysis.id

    return result
