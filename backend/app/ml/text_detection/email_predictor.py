import json
import math
import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[4]

MODEL_FILE = (
    PROJECT_ROOT
    / "ml"
    / "models"
    / "email"
    / "email_naive_bayes.json"
)

TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9]+")
URL_PATTERN = re.compile(
    r"https?://\S+|www\.\S+",
    re.IGNORECASE
)


def tokenize(text: str):
    return TOKEN_PATTERN.findall(text.lower())


def load_model():
    if not MODEL_FILE.exists():
        raise FileNotFoundError(
            f"Email model not found: {MODEL_FILE}"
        )

    with open(MODEL_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


MODEL = load_model()


def predict_email(subject: str = "", body: str = ""):
    subject = subject or ""
    body = body or ""

    text = f"{subject} {body}"
    tokens = tokenize(text)

    scores = {}

    for label in ["0", "1"]:
        score = MODEL["log_prior"][label]
        word_probs = MODEL["log_prob"][label]

        for token in tokens:
            if token in word_probs:
                score += word_probs[token]

        scores[label] = score

    max_score = max(scores.values())

    ham_score = math.exp(scores["0"] - max_score)
    spam_score = math.exp(scores["1"] - max_score)

    total = ham_score + spam_score

    ham_probability = ham_score / total
    spam_probability = spam_score / total

    classification = (
        "SPAM"
        if spam_probability >= 0.5
        else "HAM"
    )

    urls = URL_PATTERN.findall(text)

    confidence = max(
        spam_probability,
        ham_probability
    )

    return {
        "classification": classification,
        "spam_probability": spam_probability,
        "ham_probability": ham_probability,
        "confidence": confidence,
        "contains_url": len(urls) > 0,
        "url_count": len(urls),
    }