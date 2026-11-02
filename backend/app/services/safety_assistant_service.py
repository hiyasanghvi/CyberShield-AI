
import re


SAFETY_SCENARIOS = [
    {
        "key": "MONEY_LOST",
        "patterns": [
            r"money.*(lost|deducted|stolen)",
            r"amount.*(debited|deducted)",
            r"fraud.*transaction",
            r"paise.*(kat|chori|gaye)",
            r"account.*(debit|empty)",
        ],
        "title": "Possible financial fraud",
        "urgency": "IMMEDIATE",
        "steps": [
            "Immediately contact your bank using its official app or verified phone number.",
            "Call India's cyber fraud helpline 1930 as soon as possible.",
            "Report the incident at https://www.cybercrime.gov.in/",
            "Block or freeze affected cards, UPI or banking access through official bank channels.",
            "Save transaction IDs, SMS alerts and screenshots as evidence.",
        ],
    },
    {
        "key": "OTP_SHARED",
        "patterns": [
            r"shared.*otp",
            r"gave.*otp",
            r"told.*otp",
            r"otp.*share",
            r"otp.*de diya",
        ],
        "title": "You may have exposed your OTP",
        "urgency": "HIGH",
        "steps": [
            "Contact your bank immediately if the OTP was related to banking or payments.",
            "Check recent transactions using the official banking app.",
            "Change affected account credentials from a trusted device.",
            "Block suspicious transactions or access through official bank support.",
            "If money was lost, call 1930 and report at cybercrime.gov.in.",
        ],
    },
    {
        "key": "UPI_PIN_SHARED",
        "patterns": [
            r"upi pin.*(shared|told|entered)",
            r"shared.*upi pin",
            r"entered.*pin.*unknown",
            r"upi pin.*de diya",
        ],
        "title": "Your UPI account may be at risk",
        "urgency": "IMMEDIATE",
        "steps": [
            "Open your official UPI app and check recent transactions.",
            "Contact your bank or UPI app support immediately.",
            "Change your UPI PIN using the official app if you suspect exposure.",
            "Raise a dispute for any unauthorized transaction.",
            "If money was lost, call 1930 and report at cybercrime.gov.in.",
        ],
    },
    {
        "key": "SUSPICIOUS_LINK_OPENED",
        "patterns": [
            r"clicked.*link",
            r"opened.*link",
            r"link.*open",
            r"click.*kar diya",
            r"link.*khul",
        ],
        "title": "You opened a suspicious link",
        "urgency": "HIGH",
        "steps": [
            "Close the suspicious page. Do not enter any further information.",
            "If you entered a password, change it using the official website or app.",
            "If you entered banking details or OTP, contact your bank immediately.",
            "Check your device for unexpected downloads or permission requests.",
            "If a transaction occurred, call 1930 and report it at cybercrime.gov.in.",
        ],
    },
    {
        "key": "APK_INSTALLED",
        "patterns": [
            r"installed.*apk",
            r"unknown.*app.*install",
            r"app.*install.*unknown",
            r"apk.*install",
        ],
        "title": "You installed an unknown application",
        "urgency": "HIGH",
        "steps": [
            "Disconnect the device from the internet if you suspect active misuse.",
            "Do not open the suspicious application again.",
            "Review and revoke unusual Accessibility, SMS and device-admin permissions.",
            "Uninstall the application if safe to do so.",
            "From a trusted device, secure your banking and important accounts.",
            "Contact your bank immediately if financial information may be exposed.",
        ],
    },
    {
        "key": "REMOTE_ACCESS",
        "patterns": [
            r"remote access",
            r"anydesk",
            r"teamviewer",
            r"screen sharing",
            r"shared.*screen",
        ],
        "title": "Possible remote-access scam",
        "urgency": "HIGH",
        "steps": [
            "End the screen-sharing or remote-access session immediately.",
            "Disconnect the device from the internet if remote control continues.",
            "Uninstall unknown remote-access applications.",
            "Review banking transactions and contact your bank if needed.",
            "Change important passwords from a separate trusted device.",
        ],
    },
]


def get_safety_advice(message: str, language: str = "hinglish") -> dict:
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Please describe your problem.")

    if len(message) > 5000:
        raise ValueError("Message is too long. Maximum 5000 characters.")

    text = message.lower()

    for scenario in SAFETY_SCENARIOS:
        if any(
            re.search(pattern, text, re.IGNORECASE)
            for pattern in scenario["patterns"]
        ):
            return {
                "scenario": scenario["key"],
                "title": scenario["title"],
                "urgency": scenario["urgency"],
                "language": language,
                "message": (
                    "Stay calm. Take these steps immediately, "
                    "and use only official bank or government channels."
                ),
                "steps": scenario["steps"],
                "official_resources": {
                    "cybercrime_helpline": "1930",
                    "cybercrime_portal": "https://www.cybercrime.gov.in/",
                },
                "disclaimer": (
                    "This is general safety guidance, not a substitute "
                    "for your bank's official fraud-response process."
                ),
            }

    return {
        "scenario": "GENERAL_CYBER_SAFETY",
        "title": "Cyber safety guidance",
        "urgency": "NORMAL",
        "language": language,
        "message": (
            "Do not share sensitive information or act on unexpected "
            "requests until you verify them independently."
        ),
        "steps": [
            "Do not share OTPs, passwords, PINs or recovery codes.",
            "Do not install apps or open attachments from unknown senders.",
            "Verify messages using the official app, website or phone number.",
            "If money was lost, call 1930 and report at cybercrime.gov.in.",
        ],
        "official_resources": {
            "cybercrime_helpline": "1930",
            "cybercrime_portal": "https://www.cybercrime.gov.in/",
        },
        "disclaimer": (
            "This assistant provides rule-based safety guidance. "
            "For urgent financial fraud, contact your bank immediately."
        ),
    }
