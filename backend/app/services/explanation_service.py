
from typing import Any


RISK_LABELS = {
    "LOW_RISK": "Low Risk",
    "LEGITIMATE": "Looks Safe",
    "SUSPICIOUS": "Suspicious",
    "PHISHING": "Phishing Risk",
    "MALICIOUS": "High Risk",
    "CRITICAL": "Critical Risk",
}


EXPLANATIONS = {
    "URL": {
        "PHISHING": (
            "This link contains patterns associated with phishing "
            "or suspicious websites."
        ),
        "LEGITIMATE": (
            "No major risk was identified by the current URL checks. "
            "This does not guarantee that the website is completely safe."
        ),
        "LOW_RISK": "No strong suspicious URL indicators were detected.",
        "SUSPICIOUS": "This link has some unusual characteristics and needs caution.",
        "MALICIOUS": "The URL analysis identified strong suspicious indicators.",
    },
    "EMAIL": {
        "PHISHING": "This email contains signs commonly associated with phishing.",
        "SUSPICIOUS": "Some parts of this email look unusual or potentially deceptive.",
        "LOW_RISK": "No strong phishing indicators were detected in this email.",
        "LEGITIMATE": "No major suspicious email indicators were identified.",
    },
    "SMS": {
        "PHISHING": "This message may be attempting to trick you into sharing information.",
        "SUSPICIOUS": "This message contains suspicious language or links.",
        "LOW_RISK": "No strong scam indicators were detected in this message.",
        "LEGITIMATE": "No major suspicious message indicators were identified.",
    },
    "QR": {
        "PHISHING": "The QR code leads to a URL with suspicious characteristics.",
        "SUSPICIOUS": "The QR destination needs to be checked before opening.",
        "LOW_RISK": "No strong suspicious indicators were detected in the QR destination.",
        "LEGITIMATE": "The QR destination passed the current checks.",
    },
    "APK": {
        "MALICIOUS": "The APK contains indicators that may be associated with harmful app behaviour.",
        "SUSPICIOUS": "Some app permissions or code references need further investigation.",
        "LOW_RISK": "No strong malware indicators were identified by the current static checks.",
        "LEGITIMATE": "No major suspicious indicators were identified by the current checks.",
    },
    "NETWORK": {
        "MALICIOUS": "The network capture contains strong suspicious traffic patterns.",
        "SUSPICIOUS": "The captured network traffic contains patterns that need investigation.",
        "LOW_RISK": "No strong attack patterns were detected by the current network checks.",
        "LEGITIMATE": "No major suspicious network indicators were identified.",
    },
}


ACTIONS = {
    "URL": [
        "Do not enter your password, OTP or banking details on an unverified website.",
        "Open the official website or app directly instead of using the shared link.",
    ],
    "EMAIL": [
        "Do not open unexpected attachments or click suspicious links.",
        "Verify the sender using an independent official contact method.",
    ],
    "SMS": [
        "Do not reply with OTP, PIN, password or banking information.",
        "Verify payment, KYC or account-related claims through the official app.",
    ],
    "QR": [
        "Do not enter personal or payment information on an unverified destination.",
        "Check the destination URL before proceeding.",
    ],
    "APK": [
        "Do not install the app unless its source and publisher are verified.",
        "Review sensitive permissions and install apps from trusted sources.",
    ],
    "NETWORK": [
        "Investigate the flagged IP addresses and traffic patterns.",
        "Correlate findings with firewall and endpoint logs before taking action.",
    ],
}


INDICATOR_EXPLANATIONS = {
    "POSSIBLE_PORT_SCAN": "One source contacted many different destination ports.",
    "POSSIBLE_SYN_FLOOD": "A high number of TCP SYN packets was observed from a source.",
    "DNS_TRAFFIC_PRESENT": "DNS traffic was present in the capture.",
    "HTTP_TRAFFIC_PRESENT": "Traffic using HTTP port 80 was observed.",
    "NO_STRONG_NETWORK_INDICATORS": "No strong network attack pattern was detected.",
}


def _normalise(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().upper()


def _get_reasons(module: str, result: dict) -> list[str]:
    reasons = []

    indicators = result.get("indicators", [])

    if isinstance(indicators, list):
        for indicator in indicators:
            key = _normalise(indicator)
            explanation = INDICATOR_EXPLANATIONS.get(key)

            if explanation:
                reasons.append(explanation)

    if module == "APK":
        permissions = result.get("suspicious_permissions", [])
        apis = result.get("suspicious_apis", [])

        if permissions:
            reasons.append(
                f"{len(permissions)} suspicious permission reference(s) "
                "were flagged for review."
            )

        if apis:
            reasons.append(
                f"{len(apis)} suspicious API reference(s) were found "
                "in the app's code strings."
            )

        if result.get("exported_components"):
            reasons.append(
                "The app contains exported Android components. "
                "Exported components are not automatically vulnerabilities."
            )

    if module == "URL" and result.get("explanation"):
        reasons.append(str(result["explanation"]))

    if module == "EMAIL" and result.get("explanation"):
        reasons.append(str(result["explanation"]))

    if module == "SMS" and result.get("explanation"):
        reasons.append(str(result["explanation"]))

    if module == "NETWORK" and result.get("evidence"):
        for item in result["evidence"]:
            description = item.get("description")
            if description and description not in reasons:
                reasons.append(description)

    # Keep output concise and avoid duplicate reasons.
    unique_reasons = []
    for reason in reasons:
        if reason not in unique_reasons:
            unique_reasons.append(reason)

    return unique_reasons[:6]


def generate_safety_explanation(
    module: str,
    result: dict,
    language: str = "hinglish",
) -> dict:

    module = _normalise(module)
    classification = _normalise(result.get("classification"))

    risk_score = result.get("risk_score", 0)

    try:
        risk_score = max(0, min(100, int(risk_score or 0)))
    except (TypeError, ValueError):
        risk_score = 0

    risk_label = RISK_LABELS.get(
        classification,
        "Needs Review",
    )

    module_explanations = EXPLANATIONS.get(module, {})

    summary = module_explanations.get(
        classification,
        "The analysis is complete. Review the findings before taking action.",
    )

    actions = ACTIONS.get(
        module,
        ["Review the findings carefully before taking action."],
    )

    reasons = _get_reasons(module, result)

    if not reasons:
        reasons = [
            "The current analysis did not provide additional detailed indicators."
        ]

    if language.lower() in ("hi", "hindi"):
        summary = (
            f"Is analysis mein result '{risk_label}' aaya hai. "
            "Neeche diye gaye points ko dhyan se dekhein."
        )
        actions = [
            "Koi bhi OTP, PIN ya password share na karein.",
            "Official app ya website se information verify karein.",
        ]

    elif language.lower() in ("en", "english"):
        summary = (
            f"The analysis result is '{risk_label}'. "
            "Please review the findings below."
        )

    return {
        "module": module,
        "classification": classification,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "summary": summary,
        "why_flagged": reasons,
        "recommended_actions": actions,
        "disclaimer": (
            "This is an automated assessment based on available indicators. "
            "It is not a guarantee that content is safe or malicious."
        ),
    }
