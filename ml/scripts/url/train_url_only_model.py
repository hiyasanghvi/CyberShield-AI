from pathlib import Path
import csv
import sys

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)
import joblib


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

MODEL_DIR = (
    PROJECT_ROOT
    / "ml"
    / "models"
    / "url"
)

MODEL_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# IMPORT LIVE FEATURE EXTRACTOR
# ============================================================

BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

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
# CHECK DATASET
# ============================================================

if not DATASET_PATH.exists():
    raise FileNotFoundError(
        f"Dataset not found:\n{DATASET_PATH}"
    )


# ============================================================
# LOAD DATASET + GENERATE FEATURES USING OUR LIVE EXTRACTOR
# ============================================================

X = []
y = []

print("\n========================================")
print("BUILDING URL-ONLY FEATURE DATASET")
print("========================================")

with open(
    DATASET_PATH,
    "r",
    encoding="utf-8",
    errors="ignore",
    newline=""
) as file:

    reader = csv.DictReader(file)

    for row_number, row in enumerate(reader, start=1):

        url = row["URL"].strip()

        if not url:
            continue

        try:
            extracted = extract_url_features(url)

            feature_vector = [
                float(extracted[feature])
                for feature in FEATURES
            ]

            label = int(row["label"])

            X.append(feature_vector)
            y.append(label)

        except Exception as error:
            print(
                f"Skipping row {row_number}: {error}"
            )


print(f"Samples loaded : {len(X)}")
print(f"Features       : {len(FEATURES)}")


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)


print("\n========================================")
print("TRAINING URL-ONLY RANDOM FOREST")
print("========================================")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1,
)

model.fit(X_train, y_train)


# ============================================================
# PREDICTION
# ============================================================

y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]


# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, y_prob)

cm = confusion_matrix(y_test, y_pred)


# ============================================================
# PRINT RESULTS
# ============================================================

print("\n========================================")
print("URL-ONLY MODEL RESULTS")
print("========================================")

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")
print(f"ROC-AUC   : {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(cm)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

print("\n========================================")
print("TOP FEATURE IMPORTANCES")
print("========================================")

importances = model.feature_importances_

feature_importance = sorted(
    zip(FEATURES, importances),
    key=lambda item: item[1],
    reverse=True,
)

for feature, importance in feature_importance:
    print(
        f"{feature:30} : {importance:.6f}"
    )


# ============================================================
# SAVE MODEL
# ============================================================

model_path = (
    MODEL_DIR
    / "url_urlonly_random_forest.joblib"
)

joblib.dump(model, model_path)


# ============================================================
# SAVE METADATA
# ============================================================

metadata_path = (
    MODEL_DIR
    / "url_urlonly_metadata.json"
)

import json

metadata = {
    "model_type": "RandomForestClassifier",
    "n_estimators": 200,
    "feature_count": len(FEATURES),
    "features": FEATURES,
    "training_samples": len(X_train),
    "testing_samples": len(X_test),
    "accuracy": accuracy,
    "precision": precision,
    "recall": recall,
    "f1_score": f1,
    "roc_auc": roc_auc,
    "confusion_matrix": cm.tolist(),
    "purpose": "Deployable URL-only phishing detection model",
}

with open(
    metadata_path,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        metadata,
        file,
        indent=4,
    )


print("\n========================================")
print("MODEL SAVED")
print("========================================")

print(f"Model    : {model_path}")
print(f"Metadata : {metadata_path}")

print("\nURL-only model training completed.")