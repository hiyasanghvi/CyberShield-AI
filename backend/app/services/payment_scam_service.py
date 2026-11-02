
import re
from typing import Any


SCAM_RULES = [
    {
        "name": "OTP_OR_PIN_REQUEST",
        "weight": 35,
        "patterns": [
            r"\bshare\b.{0,25}\botp\b",
            r"\bsend\b.{0,25}\botp\b",
            r"\benter\b.{0,25}\botp\b",
            r"\bshare\b.{0,25}\bupi pin\b",
            r"\bprovide\b.{0,25}\bpin\b",
            r"\bpassword\b.{0,25}\bverify\b",
        ],
        "reason": "The message asks for an OTP, PIN or password.",
        "action": "Never share your OTP, UPI PIN or banking password.",
    },
    {
        "name": "KYC_URGENCY",
        "weight": 25,
        "patterns": [
            r"\bkyc\b.{0,60}\b(expir|block|suspend|update|verify)\w*",
            r"\b(account|bank)\b.{0,50}\b(block|suspend|freeze)\w*",
            r"\bwithin\s+\d+\s+hours?\b",
            r"\bimmediately\s+verify\b",
        ],
        "reason": "The message uses account-blocking or urgent KYC language.",
        "action": "Check KYC status only through your bank's official app or branch.",
    },
    {
        "name": "FAKE_REWARD_OR_REFUND",
        "weight": 20,
        "patterns": [
            r"\b(you have won|won a prize|lucky winner)\b",
            r"\b(claim|receive|get)\b.{0,35}\b(refund|reward|cashback|prize)\b",
            r"\bfree money\b",
            r"\bcashback\b.{0,40}\b(click|claim|link)\b",
        ],
        "reason": "The message promises an unexpected reward, refund or cashback.",
        "action": "Verify refunds and rewards directly with the official service.",
    },
    {
        "name": "UPI_COLLECT_REQUEST",
        "weight": 30,
        "patterns": [
            r"\b(collect request|payment request|request money)\b",
            r"\bapprove\b.{0,40}\b(payment|collect|request)\b",
            r"\benter\b.{0,30}\bupi pin\b.{0,30}\b(receive|get|claim)\b",
            r"\bscan\b.{0,30}\bqr\b.{0,40}\b(receive|get)\b",
        ],
        "reason": "The message may be asking you to approve a payment request.",
        "action": "Read the UPI app screen carefully. Entering a UPI PIN authorizes a payment, not receipt of money.",
    },
    {
        "name": "REMOTE_ACCESS_REQUEST",
        "weight": 30,
        "patterns": [
            r"\b(anydesk|teamviewer|remote access|screen sharing)\b",
            r"\binstall\b.{0,40}\b(remote|support)\b.{0,20}\bapp\b",
        ],
        "reason": "The message refers to remote-access or screen-sharing software.",
        "action": "Do not grant remote access to unknown callers or support agents.",
    },
    {
        "name": "SUSPICIOUS_LINK",
        "weight": 20,
        "patterns": [
            r"https?://[^\s]+",
            r"\b(bit\.ly|tinyurl\.com|t\.co)/\S+",
        ],
        "reason": "The message contains a link that should be verified before opening.",
        "action": "Do not open unexpected links. Visit the official website directly.",
    },
    {
        "name": "THREAT_OR_URGENCY",
        "weight": 10,
        "patterns": [
            r"\baccount will be blocked\b",
            r"\blast warning\b",
            r"\bact now\b",
            r"\bwithin \d+ minutes\b",
            r"\bimmediate action required\b",
        ],
        "reason": "The message uses pressure or threatening language.",
        "action": "Pause and verify the claim independently before acting.",
    },
]


def analyze_payment_message(message: str) -> dict[str, Any]:
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Please provide a message to analyze.")

    if len(message) > 20000:
        raise ValueError("Message is too long. Maximum length is 20,000 characters.")

    normalized = message.lower()
    detected = []
    actions = []
    score = 0

    for rule in SCAM_RULES:
        matched = any(
            re.search(pattern, normalized, re.IGNORECASE)
            for pattern in rule["patterns"]
        )

        if matched:
            detected.append({
                "indicator": rule["name"],
                "reason": rule["reason"],
                "weight": rule["weight"],
            })
            score += rule["weight"]
            actions.append(rule["action"])

    score = min(score, 100)

    if score >= 60:
        classification = "SUSPICIOUS"
        severity = "HIGH"
    elif score >= 30:
        classification = "SUSPICIOUS"
        severity = "MEDIUM"
    elif score > 0:
        classification = "CAUTION"
        severity = "LOW"
    else:
        classification = "LOW_RISK"
        severity = "LOW"

    if not detected:
        actions = [
            "No strong payment scam indicators were detected.",
            "Still verify payment requests using your official banking app.",
        ]

    unique_actions = list(dict.fromkeys(actions))

    return {
        "classification": classification,
        "risk_score": score,
        "severity": severity,
        "detected_indicators": detected,
        "explanation": (
            f"Detected {len(detected)} payment-related suspicious indicator(s)."
            if detected
            else "No strong payment scam indicators were found in the provided text."
        ),
        "recommended_actions": unique_actions,
        "disclaimer": (
            "This is a rule-based warning system. It cannot verify an actual "
            "UPI transaction, bank account, payment receiver or screenshot authenticity."
        ),
    }
