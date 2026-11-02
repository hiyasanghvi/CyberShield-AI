
from urllib.parse import urlparse


# Curated allowlist for the initial project implementation.
# Add domains only after verifying that they are genuinely controlled
# by the organization. Do not add hosting platforms such as github.io.
TRUSTED_DOMAINS = {
    "google.com",
    "youtube.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "wikipedia.org",
    "github.com",
    "linkedin.com",
    "stackoverflow.com",
    "openai.com",
    "example.com",
}


def get_domain_reputation(domain: str | None) -> dict:
    """
    Check a hostname against CyberShield's curated domain list.

    This is a local allowlist, not a live reputation service.
    Unknown domains remain UNKNOWN.
    """

    if not domain:
        return {
            "status": "UNKNOWN",
            "domain": None,
            "reason": "Domain could not be identified.",
        }

    hostname = domain.strip().lower().rstrip(".")

    # Remove www. for canonical comparison.
    if hostname.startswith("www."):
        hostname = hostname[4:]

    for trusted_domain in TRUSTED_DOMAINS:
        if hostname == trusted_domain:
            return {
                "status": "TRUSTED_LIST",
                "domain": hostname,
                "reason": (
                    "The domain matches CyberShield's curated "
                    "trusted-domain list."
                ),
            }

    return {
        "status": "UNKNOWN",
        "domain": hostname,
        "reason": (
            "The domain is not present in CyberShield's "
            "local trusted-domain list."
        ),
    }


def calculate_url_risk(
    phishing_probability: float,
    classification: str,
    features: dict,
) -> dict:

    phishing_probability = max(
        0.0,
        min(1.0, float(phishing_probability))
    )

    ml_classification = classification.upper().strip()
    base_score = phishing_probability * 100

    domain = features.get("Domain")
    reputation = get_domain_reputation(domain)

    indicators = []

    # URL structure indicators
    if features.get("IsDomainIP") == 1:
        indicators.append(
            "The URL uses an IP address instead of a normal domain."
        )

    if features.get("HasObfuscation") == 1:
        indicators.append(
            "The URL contains potentially obfuscated characters."
        )

    if features.get("NoOfSubDomain", 0) >= 3:
        indicators.append(
            "The URL contains multiple subdomain levels."
        )

    if features.get("NoOfQMark", 0) >= 2:
        indicators.append(
            "The URL contains multiple query delimiters."
        )

    if features.get("NoOfEqualsInURL", 0) >= 3:
        indicators.append(
            "The URL contains several parameter assignments."
        )

    if features.get("NoOfDegitsInURL", 0) >= 5:
        indicators.append(
            "The URL contains a relatively high number of digits."
        )

    if features.get("URLLength", 0) >= 100:
        indicators.append(
            "The URL is unusually long."
        )

    if features.get("IsHTTPS") == 0:
        indicators.append(
            "The URL does not use HTTPS. HTTPS alone does not prove safety."
        )

    # Domain reputation context
    if reputation["status"] == "TRUSTED_LIST":
        indicators.append(
            "The hostname matches CyberShield's curated trusted-domain list. "
            "This is supporting evidence, not a guarantee that the URL is safe."
        )
    else:
        indicators.append(
            "No trusted-domain match was found. The domain's reputation "
            "is currently unknown."
        )

    # Initial risk score
    risk_score = base_score

    # Resolve known false positives from the ML model using the
    # curated hostname list. Preserve the original ML prediction.
    if reputation["status"] == "TRUSTED_LIST":
        risk_score = min(risk_score, 20.0)

        final_classification = "LEGITIMATE"

        explanation = (
            "The ML model flagged this URL as potentially phishing, "
            "but its hostname matches CyberShield's curated trusted-domain "
            "list. The final risk score has therefore been reduced. "
            "This does not guarantee that the specific URL or page is safe."
        )

    else:
        final_classification = ml_classification

        if ml_classification == "PHISHING":
            risk_score = max(risk_score, 61.0)

            explanation = (
                "The machine-learning model classified this URL as "
                "potentially phishing. The risk score is primarily based "
                "on the model's phishing probability and URL-level evidence."
            )
        else:
            explanation = (
                "The machine-learning model classified this URL as "
                "legitimate based on its learned URL-level patterns. "
                "The domain is not present in the local trusted-domain list, "
                "so this result should not be treated as a reputation guarantee."
            )

    risk_score = round(max(0.0, min(100.0, risk_score)))

    if risk_score <= 30:
        severity = "LOW"
    elif risk_score <= 60:
        severity = "MEDIUM"
    elif risk_score <= 80:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    if severity == "CRITICAL":
        recommendation = (
            "Do not open or share this URL. Treat it as potentially malicious."
        )
    elif severity == "HIGH":
        recommendation = (
            "Exercise extreme caution. Verify the URL and its source independently."
        )
    elif severity == "MEDIUM":
        recommendation = (
            "Proceed cautiously and verify the URL and its source before opening."
        )
    else:
        recommendation = (
            "No high-risk signals were identified by the current assessment. "
            "Still verify the source before entering sensitive information."
        )

    return {
        "classification": final_classification,
        "ml_classification": ml_classification,
        "risk_score": risk_score,
        "severity": severity,
        "explanation": explanation,
        "indicators": indicators,
        "recommendation": recommendation,
        "domain_reputation": reputation,
    }
