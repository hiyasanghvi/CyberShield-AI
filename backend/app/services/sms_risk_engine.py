import re


def calculate_sms_risk(
    spam_probability: float,
    classification: str,
    text: str,
) -> dict:

    spam_probability = max(
        0.0,
        min(1.0, float(spam_probability))
    )

    classification = (
        classification.upper().strip()
    )

    text_lower = text.lower()

    indicators = []


    # --------------------------------------------------
    # URL indicator
    # --------------------------------------------------

    if re.search(
        r"https?://|www\.",
        text_lower
    ):

        indicators.append(
            "The SMS contains a web link."
        )


    # --------------------------------------------------
    # Urgency indicators
    # --------------------------------------------------

    urgency_keywords = [
        "urgent",
        "immediately",
        "act now",
        "limited time",
        "hurry",
        "expires",
        "last chance",
        "now",
    ]

    urgency_found = [
        keyword
        for keyword in urgency_keywords
        if keyword in text_lower
    ]

    if urgency_found:

        indicators.append(
            "The SMS uses urgency or pressure "
            "to encourage immediate action."
        )


    # --------------------------------------------------
    # Money / reward indicators
    # --------------------------------------------------

    money_keywords = [
        "cash",
        "money",
        "reward",
        "prize",
        "won",
        "winner",
        "payment",
        "refund",
        "bonus",
        "offer",
        "free",
    ]

    money_found = [
        keyword
        for keyword in money_keywords
        if keyword in text_lower
    ]

    if money_found:

        indicators.append(
            "The SMS contains money, reward, "
            "prize, or promotional language."
        )


    # --------------------------------------------------
    # Credential / account indicators
    # --------------------------------------------------

    credential_keywords = [
        "password",
        "otp",
        "pin",
        "verify your account",
        "account suspended",
        "account blocked",
        "login",
        "security code",
    ]

    credential_found = [
        keyword
        for keyword in credential_keywords
        if keyword in text_lower
    ]

    if credential_found:

        indicators.append(
            "The SMS may be attempting to obtain "
            "account or authentication information."
        )


    # --------------------------------------------------
    # Phone number indicator
    # --------------------------------------------------

    if re.search(
        r"\+?\d[\d\s-]{8,}\d",
        text
    ):

        indicators.append(
            "The SMS contains a phone number."
        )


    # --------------------------------------------------
    # Exclamation indicator
    # --------------------------------------------------

    if text.count("!") >= 2:

        indicators.append(
            "The SMS uses multiple exclamation marks "
            "to emphasize its message."
        )


    # --------------------------------------------------
    # Base risk
    # --------------------------------------------------

    risk_score = spam_probability * 100


    # Add controlled rule-based evidence
    if urgency_found:
        risk_score += 5

    if money_found:
        risk_score += 5

    if credential_found:
        risk_score += 8

    if re.search(
        r"https?://|www\.",
        text_lower
    ):
        risk_score += 8


    risk_score = min(
        100,
        risk_score
    )


    # --------------------------------------------------
    # Classification-aware minimum risk
    # --------------------------------------------------

    if classification == "SPAM":

        risk_score = max(
            risk_score,
            61
        )


    risk_score = round(
        risk_score
    )


    # --------------------------------------------------
    # Severity
    # --------------------------------------------------

    if risk_score <= 30:

        severity = "LOW"

    elif risk_score <= 60:

        severity = "MEDIUM"

    elif risk_score <= 80:

        severity = "HIGH"

    else:

        severity = "CRITICAL"


    # --------------------------------------------------
    # Explanation
    # --------------------------------------------------

    if classification == "SPAM":

        explanation = (
            "The machine-learning model classified "
            "this SMS as potentially spam. "
            "The risk score combines the model's "
            "spam probability with detected "
            "message-level security indicators."
        )

    else:

        explanation = (
            "The machine-learning model classified "
            "this SMS as likely legitimate based "
            "on its learned text patterns."
        )


    # --------------------------------------------------
    # Recommendation
    # --------------------------------------------------

    if severity == "CRITICAL":

        recommendation = (
            "Do not click links, share credentials, "
            "send money, or respond to this message. "
            "Verify the sender through an independent "
            "trusted channel."
        )

    elif severity == "HIGH":

        recommendation = (
            "Exercise strong caution. Verify the "
            "sender and any requested action before "
            "responding."
        )

    elif severity == "MEDIUM":

        recommendation = (
            "Review the sender and message carefully "
            "before taking any action."
        )

    else:

        recommendation = (
            "No major spam indicators were detected "
            "by the current SMS analysis."
        )


    # --------------------------------------------------
    # Fallback indicator
    # --------------------------------------------------

    if not indicators:

        indicators.append(
            "No additional SMS-level security "
            "indicators were detected."
        )


    return {

        "risk_score": risk_score,

        "severity": severity,

        "explanation": explanation,

        "indicators": indicators,

        "recommendation": recommendation,
    }