import json
import math
import re
from collections import Counter
from pathlib import Path


# =========================================================
# MODEL PATH
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[4]

MODEL_PATH = (
    PROJECT_ROOT
    / "ml"
    / "models"
    / "sms"
    / "sms_tfidf_logistic.json"
)


# =========================================================
# LOAD MODEL
# =========================================================

with open(
    MODEL_PATH,
    "r",
    encoding="utf-8",
) as file:

    MODEL = json.load(file)


VOCABULARY = MODEL["vocabulary"]

IDF = MODEL["idf"]

WEIGHTS = MODEL["weights"]

BIAS = MODEL["bias"]


# =========================================================
# TOKENIZATION
# =========================================================

def tokenize(text: str) -> list[str]:

    text = text.lower()

    tokens = re.findall(
        r"[a-z0-9]+",
        text
    )

    bigrams = [
        tokens[i] + "_" + tokens[i + 1]
        for i in range(len(tokens) - 1)
    ]

    return tokens + bigrams


# =========================================================
# SIGMOID
# =========================================================

def sigmoid(value: float) -> float:

    value = max(
        -50.0,
        min(50.0, value)
    )

    return 1.0 / (
        1.0 + math.exp(-value)
    )


# =========================================================
# TF-IDF TRANSFORMATION
# =========================================================

def transform_text(text: str) -> list[float]:

    tokens = tokenize(text)

    counts = Counter(tokens)

    total_tokens = len(tokens)

    vector = [
        0.0
        for _ in range(len(VOCABULARY))
    ]

    if total_tokens == 0:
        return vector

    for token, count in counts.items():

        if token not in VOCABULARY:
            continue

        index = VOCABULARY[token]

        tf = count / total_tokens

        vector[index] = (
            tf * IDF[index]
        )

    # L2 normalization
    norm = math.sqrt(
        sum(
            value * value
            for value in vector
        )
    )

    if norm > 0:

        vector = [
            value / norm
            for value in vector
        ]

    return vector


# =========================================================
# PREDICT SMS
# =========================================================

def predict_sms(text: str) -> dict:

    if not isinstance(text, str):

        raise ValueError(
            "SMS must be a string."
        )

    text = text.strip()

    if not text:

        raise ValueError(
            "SMS cannot be empty."
        )

    vector = transform_text(text)

    # Logistic regression dot product
    score = BIAS

    for value, weight in zip(
        vector,
        WEIGHTS
    ):

        score += (
            value * weight
        )

    spam_probability = sigmoid(score)

    ham_probability = (
        1.0 - spam_probability
    )

    if spam_probability >= 0.5:

        classification = "SPAM"

        confidence = spam_probability

    else:

        classification = "HAM"

        confidence = ham_probability

    return {
        "text": text,
        "classification": classification,
        "spam_probability": spam_probability,
        "ham_probability": ham_probability,
        "confidence": confidence,
    }