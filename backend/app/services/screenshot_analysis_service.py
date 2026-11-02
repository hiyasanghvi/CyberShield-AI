
import io
import os
import re

from PIL import Image, ImageOps, ImageEnhance
import pytesseract
from pytesseract import Output

from app.services.payment_scam_service import analyze_payment_message


TESSERACT_PATH = os.getenv(
    "TESSERACT_CMD",
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
)

if os.path.exists(TESSERACT_PATH):
    pytesseract.pytesseract.tesseract_cmd = TESSERACT_PATH

MAX_IMAGE_SIZE = 10 * 1024 * 1024
MAX_IMAGE_DIMENSION = 4000

# Words that indicate the screenshot may be about banking,
# payments, accounts, messages or online transactions.
CONTEXT_WORDS = {
    "bank", "banking", "account", "kyc", "upi", "payment",
    "transaction", "otp", "refund", "cashback", "debit",
    "credit", "blocked", "suspended", "verify", "verification",
    "password", "pin", "wallet", "card", "invoice", "delivery",
    "parcel", "courier", "lottery", "prize", "winner", "claim",
    "urgent", "警告",
}


def extract_text_and_confidence(image_bytes: bytes):
    if not image_bytes:
        raise ValueError("Uploaded image is empty.")

    if len(image_bytes) > MAX_IMAGE_SIZE:
        raise ValueError("Image exceeds the 10 MB limit.")

    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.verify()

        image = Image.open(io.BytesIO(image_bytes))
        image = ImageOps.exif_transpose(image).convert("RGB")

        if max(image.size) > MAX_IMAGE_DIMENSION:
            image.thumbnail((MAX_IMAGE_DIMENSION, MAX_IMAGE_DIMENSION))

        image = ImageOps.grayscale(image)
        image = ImageEnhance.Contrast(image).enhance(1.6)
        image = ImageEnhance.Sharpness(image).enhance(1.3)

        data = pytesseract.image_to_data(
            image,
            lang="eng",
            config="--psm 6",
            output_type=Output.DICT,
            timeout=25,
        )

        words = []
        confidences = []

        for word, confidence in zip(data["text"], data["conf"]):
            word = word.strip()

            try:
                confidence = float(confidence)
            except (TypeError, ValueError):
                continue

            if word and confidence >= 0:
                words.append(word)
                confidences.append(confidence)

        extracted_text = " ".join(words).strip()
        average_confidence = (
            round(sum(confidences) / len(confidences), 2)
            if confidences else 0
        )

        return extracted_text, average_confidence

    except pytesseract.TesseractNotFoundError as error:
        raise RuntimeError(
            "Tesseract OCR is not installed or its path is incorrect."
        ) from error

    except Exception as error:
        raise ValueError(
            "Could not read this image. Please upload a clear JPG or PNG."
        ) from error


def has_relevant_context(text: str) -> bool:
    words = set(re.findall(r"[a-zA-Z]+", text.lower()))
    return bool(words.intersection(CONTEXT_WORDS))


def analyze_screenshot(image_bytes: bytes, file_name: str) -> dict:
    extracted_text, ocr_confidence = extract_text_and_confidence(
        image_bytes
    )

    if not extracted_text or len(extracted_text) < 8:
        return {
            "file_name": file_name,
            "extracted_text": extracted_text,
            "ocr_engine": "Tesseract OCR",
            "ocr_confidence": ocr_confidence,
            "analysis_type": "SCREENSHOT_SCAM",
            "classification": "INCONCLUSIVE",
            "risk_score": 0,
            "severity": "UNKNOWN",
            "detected_indicators": [],
            "explanation": (
                "The image did not contain enough readable text "
                "to assess its safety."
            ),
            "recommended_actions": [
                "Upload a clearer screenshot.",
                "Do not open links or share OTPs from an unverified message.",
            ],
            "disclaimer": (
                "An inconclusive result does not mean the screenshot is safe."
            ),
        }

    if ocr_confidence < 35:
        return {
            "file_name": file_name,
            "extracted_text": extracted_text,
            "ocr_engine": "Tesseract OCR",
            "ocr_confidence": ocr_confidence,
            "analysis_type": "SCREENSHOT_SCAM",
            "classification": "INCONCLUSIVE",
            "risk_score": 0,
            "severity": "UNKNOWN",
            "detected_indicators": [],
            "explanation": (
                "Text recognition confidence is too low for a reliable assessment."
            ),
            "recommended_actions": [
                "Upload a sharper screenshot with readable text.",
                "Avoid acting on unexpected payment or account messages until verified.",
            ],
            "disclaimer": (
                "The system could not reliably read this image."
            ),
        }

    if not has_relevant_context(extracted_text):
        return {
            "file_name": file_name,
            "extracted_text": extracted_text,
            "ocr_engine": "Tesseract OCR",
            "ocr_confidence": ocr_confidence,
            "analysis_type": "SCREENSHOT_SCAM",
            "classification": "INCONCLUSIVE",
            "risk_score": 0,
            "severity": "UNKNOWN",
            "detected_indicators": [],
            "explanation": (
                "The screenshot does not appear to contain enough "
                "message, account or payment-related context."
            ),
            "recommended_actions": [
                "Upload the actual SMS, email, WhatsApp or payment message.",
                "You can also paste the message text into the Payment Scam Checker.",
            ],
            "disclaimer": (
                "This image was not classified as safe. Its purpose could not be determined."
            ),
        }

    result = analyze_payment_message(extracted_text)

    # A message with no rule matches is not proof of authenticity.
    if result["classification"] == "LOW_RISK":
        result["classification"] = "NO_OBVIOUS_SCAM"
        result["severity"] = "INFO"
        result["explanation"] = (
            "No obvious scam indicators were found in the readable text. "
            "The sender and message authenticity have not been verified."
        )
        result["recommended_actions"] = [
            "Verify the sender through the bank's official app or website.",
            "Never share OTP, UPI PIN or passwords.",
        ]

    return {
        "file_name": file_name,
        "extracted_text": extracted_text,
        "ocr_engine": "Tesseract OCR",
        "ocr_confidence": ocr_confidence,
        "analysis_type": "SCREENSHOT_SCAM",
        **result,
    }
