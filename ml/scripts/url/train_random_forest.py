from pathlib import Path
import csv
import json

import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
)


# ============================================================
# PATHS
# ============================================================

INPUT_PATH = Path(
    "ml/datasets/url/processed/url_features.csv"
)

MODEL_DIR = Path(
    "ml/models/url"
)

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# LOAD DATASET
# ============================================================

if not INPUT_PATH.exists():
    raise FileNotFoundError(
        f"Dataset not found: {INPUT_PATH}"
    )


with open(
    INPUT_PATH,
    "r",
    encoding="utf-8",
    newline=""
) as file:

    reader = csv.DictReader(file)
    rows = list(reader)
    columns = reader.fieldnames


FEATURES = [
    column
    for column in columns
    if column != "label"
]


X = np.array(
    [
        [
            float(row[feature])
            for feature in FEATURES
        ]
        for row in rows
    ],
    dtype=np.float64
)

y = np.array(
    [
        int(row["label"])
        for row in rows
    ],
    dtype=np.int64
)


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("\n========================================")
print("RANDOM FOREST URL CLASSIFIER")
print("========================================")

print(f"Total samples : {len(X)}")
print(f"Features      : {len(FEATURES)}")
print(f"Training      : {len(X_train)}")
print(f"Testing       : {len(X_test)}")


# ============================================================
# MODEL
# ============================================================

model = RandomForestClassifier(
    n_estimators=200,
    max_depth=None,
    min_samples_split=2,
    min_samples_leaf=1,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)


print("\nTraining Random Forest...")
model.fit(X_train, y_train)

print("Training complete.")


# ============================================================
# PREDICTION
# ============================================================

y_pred = model.predict(X_test)

y_probability = model.predict_proba(X_test)[:, 1]


# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred
)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0
)

roc_auc = roc_auc_score(
    y_test,
    y_probability
)

cm = confusion_matrix(
    y_test,
    y_pred
)


# ============================================================
# RESULTS
# ============================================================

print("\n========================================")
print("MODEL PERFORMANCE")
print("========================================")

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")
print(f"ROC-AUC   : {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Phishing",
            "Legitimate"
        ],
        zero_division=0
    )
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

feature_importance = sorted(
    zip(
        FEATURES,
        model.feature_importances_
    ),
    key=lambda x: x[1],
    reverse=True
)


print("\n========================================")
print("TOP 15 FEATURE IMPORTANCE")
print("========================================")

for rank, (feature, importance) in enumerate(
    feature_importance[:15],
    start=1
):
    print(
        f"{rank:2}. "
        f"{feature:30} "
        f"{importance:.6f}"
    )


# ============================================================
# SAVE MODEL
# ============================================================

try:

    import joblib

    model_path = MODEL_DIR / "url_random_forest.joblib"

    joblib.dump(
        model,
        model_path
    )

    print("\nModel saved:")
    print(model_path)

except ImportError:

    print(
        "\nWARNING: joblib is not installed."
    )


# ============================================================
# SAVE MODEL METADATA
# ============================================================

metadata = {
    "model": "RandomForestClassifier",
    "dataset": str(INPUT_PATH),
    "total_samples": int(len(X)),
    "training_samples": int(len(X_train)),
    "testing_samples": int(len(X_test)),
    "number_of_features": int(len(FEATURES)),
    "features": FEATURES,
    "random_state": 42,
    "n_estimators": 200,
    "metrics": {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1),
        "roc_auc": float(roc_auc),
    },
    "confusion_matrix": cm.tolist(),
}


metadata_path = MODEL_DIR / "url_random_forest_metadata.json"

with open(
    metadata_path,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        metadata,
        file,
        indent=4
    )


print("Metadata saved:")
print(metadata_path)

print("\n========================================")
print("URL MODEL TRAINING COMPLETE")
print("========================================")