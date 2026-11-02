from pathlib import Path
import csv
import sys

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[3]

DATASET_PATH = (
    PROJECT_ROOT
    / "ml"
    / "datasets"
    / "url"
    / "processed"
    / "url_dataset_clean.csv"
)

BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))


# ============================================================
# IMPORT LIVE FEATURE EXTRACTOR
# ============================================================

from app.ml.url_detection.feature_extractor import (
    extract_url_features
)


# ============================================================
# URL-ONLY FEATURES
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
# LOAD DATA
# ============================================================

X = []
y = []

print("\n========================================")
print("BUILDING URL-ONLY CROSS-VALIDATION DATA")
print("========================================")

with open(
    DATASET_PATH,
    "r",
    encoding="utf-8",
    errors="ignore",
    newline=""
) as file:

    reader = csv.DictReader(file)

    for row in reader:

        url = row["URL"].strip()

        if not url:
            continue

        extracted = extract_url_features(url)

        feature_vector = [
            float(extracted[feature])
            for feature in FEATURES
        ]

        X.append(feature_vector)
        y.append(int(row["label"]))


print(f"Samples  : {len(X)}")
print(f"Features : {len(FEATURES)}")


# ============================================================
# MODEL
# ============================================================

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1,
)


# ============================================================
# 5-FOLD STRATIFIED CROSS VALIDATION
# ============================================================

cv = StratifiedKFold(
    n_splits=5,
    shuffle=True,
    random_state=42,
)


scoring = [
    "accuracy",
    "precision",
    "recall",
    "f1",
    "roc_auc",
]


print("\n========================================")
print("RUNNING 5-FOLD CROSS VALIDATION")
print("========================================")

results = cross_validate(
    model,
    X,
    y,
    cv=cv,
    scoring=scoring,
    n_jobs=-1,
)


# ============================================================
# RESULTS
# ============================================================

print("\n========================================")
print("5-FOLD CROSS-VALIDATION RESULTS")
print("========================================")

for metric in scoring:

    scores = results[f"test_{metric}"]

    mean_score = scores.mean()
    std_score = scores.std()

    print(
        f"{metric.upper():10} : "
        f"{mean_score:.4f} ± {std_score:.4f}"
    )


# ============================================================
# INDIVIDUAL FOLD RESULTS
# ============================================================

print("\n========================================")
print("INDIVIDUAL FOLD RESULTS")
print("========================================")

for i in range(5):

    print(f"\nFold {i + 1}")

    for metric in scoring:

        score = results[f"test_{metric}"][i]

        print(
            f"  {metric.upper():10} : {score:.4f}"
        )


print("\n========================================")
print("CROSS-VALIDATION COMPLETED")
print("========================================")