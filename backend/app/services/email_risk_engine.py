import re


URGENCY_WORDS = [
    "urgent",
    "immediately",
    "action required",
    "act now",
    "verify now",
    "account suspended",
    "final warning",
    "expires",
    "limited time",
]

MONEY_WORDS = [
    "winner",
    "prize",
    "reward",
    "cash",
    "money",
    "bonus",
    "lottery",
    "free",
    "gift",
]

CREDENTIAL_WORDS = [
    "password",
    "login",
    "verify your account",
    "username",
    "otp",
    "bank account",
    "credit card",
    "security code",
]


def contains_any(text: str, words: list[str]) -> bool:
    text = text.lower()

    return any(
        word.lower() in text
        for word in words
    )


def calculate_email_risk(
    spam_probability: float,
    subject: str,
    body: str,
    contains_url: bool,
    url_count: int,
    has_attachment: bool,
):
    subject = subject or ""
    body = body or ""

    full_text = f"{subject} {body}".lower()

    score = spam_probability * 75

    indicators = []

    if contains_url:
        score += 8
        indicators.append(
            "The email contains one or more URLs."
        )

    if url_count >= 3:
        score += 5
        indicators.append(
            "The email contains multiple URLs."
        )

    if contains_any(full_text, URGENCY_WORDS):
        score += 6
        indicators.append(
            "The email uses urgency or pressure language."
        )

    if contains_any(full_text, MONEY_WORDS):
        score += 5
        indicators.append(
            "The email contains reward, money, prize, or promotional language."
        )

    if contains_any(full_text, CREDENTIAL_WORDS):
        score += 8
        indicators.append(
            "The email references credentials, account verification, or sensitive information."
        )

    if has_attachment:
        score += 4
        indicators.append(
            "The email contains an attachment."
        )

    score = min(100, round(score))

    if score <= 30:
        severity = "LOW"
    elif score <= 60:
        severity = "MEDIUM"
    elif score <= 80:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    if spam_probability >= 0.5:
        classification = "SPAM"
        score = max(score, 61)
    else:
        classification = "HAM"

    if classification == "SPAM":
        explanation = (
            "The machine-learning model classified the email as potentially "
            "spam. The risk score combines the model probability with "
            "detected email security indicators."
        )

        recommendation = (
            "Exercise caution. Verify the sender and avoid clicking links "
            "or opening unexpected attachments."
        )

    else:
        explanation = (
            "The machine-learning model classified the email as likely "
            "legitimate. The risk score also considers detected security "
            "indicators."
        )

        recommendation = (
            "No strong spam indicators were detected, but verify unexpected "
            "requests independently."
        )

    return {
        "classification": classification,
        "risk_score": score,
        "severity": severity,
        "explanation": explanation,
        "indicators": indicators,
        "recommendation": recommendation,
    }