from pathlib import Path
import sys

# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[4]

BACKEND_DIR = PROJECT_ROOT / "backend"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.ml.url_detection.portable_forest import PortableRandomForest


# ============================================================
# MODEL PATH
# ============================================================

MODEL_PATH = (
    PROJECT_ROOT
    / "ml"
    / "models"
    / "url"
    / "url_urlonly_random_forest.joblib"
)


# ============================================================
# IMPORT FEATURE EXTRACTOR
# ============================================================

from app.ml.url_detection.feature_extractor import (
    extract_url_features
)


# ============================================================
# MODEL FEATURES
# ============================================================

FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
]


# ============================================================
# LAZY MODEL LOADING
# ============================================================

_model = None


def get_model():
    global _model

    if _model is not None:
        return _model

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"URL model not found:\n{MODEL_PATH}"
        )

    try:
        _model = PortableRandomForest.load(MODEL_PATH)

        if _model.n_features != len(FEATURES):
            raise ValueError(
                f"Model has {_model.n_features} features but the URL "
                f"predictor supplies {len(FEATURES)}."
            )
        if set(_model.classes) != {0, 1}:
            raise ValueError(
                f"Expected URL model classes [0, 1], got {_model.classes}."
            )
        return _model

    except Exception as error:
        raise RuntimeError(
            "URL model loading failed: "
            f"{type(error).__name__}: {error}"
        ) from error


# ============================================================
# PREDICT URL
# ============================================================

def predict_url(url: str) -> dict:

    if not isinstance(url, str):
        raise TypeError("URL must be a string.")

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    # Extract exact training/deployment features
    extracted_features = extract_url_features(url)

    feature_vector = [
        float(extracted_features[feature])
        for feature in FEATURES
    ]

    # Load model only when URL analysis is actually requested
    model = get_model()

    prediction = model.predict(feature_vector)

    probabilities = model.predict_proba(feature_vector)

    # Dataset labels:
    # 0 = phishing
    # 1 = legitimate

    class_probabilities = dict(zip(model.classes, probabilities))
    phishing_probability = float(class_probabilities[0])
    legitimate_probability = float(class_probabilities[1])

    if prediction == 0:
        classification = "PHISHING"
    else:
        classification = "LEGITIMATE"

    confidence = max(
        phishing_probability,
        legitimate_probability
    )

    return {
        "url": url,
        "classification": classification,
        "phishing_probability": phishing_probability,
        "legitimate_probability": legitimate_probability,
        "confidence": confidence,
        "features": extracted_features,
    }
