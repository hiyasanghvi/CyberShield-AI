SEVERITY_THRESHOLDS = {
    "LOW": (0, 30),
    "MEDIUM": (31, 60),
    "HIGH": (61, 80),
    "CRITICAL": (81, 100),
}


def get_severity(score: int) -> str:
    score = max(0, min(100, int(score)))

    if score <= 30:
        return "LOW"
    elif score <= 60:
        return "MEDIUM"
    elif score <= 80:
        return "HIGH"
    else:
        return "CRITICAL"


def normalize_risk_score(
    classification: str,
    confidence: float,
    indicators_count: int = 0,
) -> int:

    classification = classification.upper()

    base_score = confidence * 100

    if classification in {
        "PHISHING",
        "SPAM",
        "MALICIOUS",
        "SUSPICIOUS",
    }:
        score = base_score
    else:
        score = base_score * 0.15

    score += min(indicators_count * 3, 15)

    return max(0, min(100, round(score)))


def build_unified_risk(
    analysis_type: str,
    classification: str,
    confidence: float,
    indicators: list[str] | None = None,
):
    indicators = indicators or []

    score = normalize_risk_score(
        classification=classification,
        confidence=confidence,
        indicators_count=len(indicators),
    )

    severity = get_severity(score)

    return {
        "analysis_type": analysis_type.upper(),
        "classification": classification.upper(),
        "confidence": round(confidence, 4),
        "risk_score": score,
        "severity": severity,
        "indicator_count": len(indicators),
    }