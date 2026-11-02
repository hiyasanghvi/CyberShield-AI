
EMERGENCY_GUIDES = {
    "money_lost": {
        "title": "Money lost through online fraud",
        "urgency": "IMMEDIATE",
        "steps": [
            "Call 1930 immediately to report the financial cyber fraud.",
            "Contact your bank using its official app or verified phone number.",
            "Ask the bank to secure the account and report the unauthorized transaction.",
            "Submit a complaint at https://www.cybercrime.gov.in/.",
            "Keep transaction ID, amount, time, SMS alerts and screenshots.",
        ],
    },
    "otp_shared": {
        "title": "OTP shared with someone",
        "urgency": "HIGH",
        "steps": [
            "Contact your bank immediately if the OTP was banking-related.",
            "Check recent account and card transactions.",
            "Change the affected account password from a trusted device.",
            "Ask your bank to secure or temporarily block affected services.",
            "If money was lost, call 1930 and report it online.",
        ],
    },
    "account_hacked": {
        "title": "Account may be hacked",
        "urgency": "HIGH",
        "steps": [
            "Use a trusted device to change your password.",
            "Sign out of other active sessions if the service provides this option.",
            "Enable two-factor authentication.",
            "Check recovery email, phone number and recent account activity.",
            "Contact the platform's official support if you cannot regain access.",
        ],
    },
    "suspicious_app": {
        "title": "Suspicious app installed",
        "urgency": "HIGH",
        "steps": [
            "Do not open or use the suspicious application.",
            "Review Accessibility, SMS and device administrator permissions.",
            "Revoke permissions you do not recognize.",
            "Uninstall the app if safe to do so.",
            "Secure banking and important accounts from a separate trusted device.",
            "Contact your bank if you entered financial information.",
        ],
    },
    "phone_lost": {
        "title": "Phone lost or stolen",
        "urgency": "HIGH",
        "steps": [
            "Contact your mobile operator to block the SIM.",
            "Use the official device-finding service to locate or secure the phone.",
            "Change important account passwords from another trusted device.",
            "Contact your bank to secure mobile banking and UPI access.",
            "Report the theft to local police where appropriate.",
        ],
    },
    "identity_shared": {
        "title": "Personal or identity details shared",
        "urgency": "MEDIUM",
        "steps": [
            "Identify exactly what information was shared.",
            "Contact the relevant bank or service if account details were exposed.",
            "Change passwords if login credentials were shared.",
            "Watch for unexpected account activity, loan messages or verification requests.",
            "Never share additional OTPs or identity documents with unknown contacts.",
        ],
    },
}


def get_emergency_guide(incident_type: str) -> dict:
    key = incident_type.strip().lower()

    guide = EMERGENCY_GUIDES.get(key)

    if not guide:
        return {
            "available_types": list(EMERGENCY_GUIDES.keys()),
            "message": "Choose a supported incident type to get its recovery steps.",
        }

    return {
        "incident_type": key,
        "title": guide["title"],
        "urgency": guide["urgency"],
        "steps": guide["steps"],
        "official_resources": {
            "cybercrime_helpline": "1930",
            "cybercrime_portal": "https://www.cybercrime.gov.in/",
        },
        "disclaimer": (
            "Follow your bank's official instructions for financial fraud. "
            "This guide does not replace emergency or law-enforcement support."
        ),
    }
