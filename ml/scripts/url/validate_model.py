from pathlib import Path
import csv

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
)


# ============================================================
# PATH
# ============================================================

INPUT_PATH = Path(
    "ml/datasets/url/processed/url_features.csv"
)


# ============================================================
# LOAD DATA
# ============================================================

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
# STRONGER VALIDATION
# ============================================================

print("\n========================================")
print("URL MODEL ROBUSTNESS VALIDATION")
print("========================================")

print(f"Total samples : {len(X)}")
print(f"Features      : {len(FEATURES)}")


# ------------------------------------------------------------
# Validation 1: Different random split
# ------------------------------------------------------------

print("\n[1] Different Train/Test Split")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=123,
    stratify=y
)

model = RandomForestClassifier(
    n_estimators=200,
    random_state=123,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)

y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

accuracy = accuracy_score(y_test, y_pred)
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
    y_prob
)

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")
print(f"ROC-AUC   : {roc_auc:.4f}")


# ------------------------------------------------------------
# Validation 2: Smaller training set
# ------------------------------------------------------------

print("\n[2] Reduced Training Data Test")

X_train_small, _, y_train_small, _ = train_test_split(
    X_train,
    y_train,
    train_size=0.50,
    random_state=321,
    stratify=y_train
)

model_small = RandomForestClassifier(
    n_estimators=200,
    random_state=321,
    n_jobs=-1,
    class_weight="balanced"
)

model_small.fit(
    X_train_small,
    y_train_small
)

y_pred_small = model_small.predict(X_test)

accuracy_small = accuracy_score(
    y_test,
    y_pred_small
)

precision_small = precision_score(
    y_test,
    y_pred_small,
    zero_division=0
)

recall_small = recall_score(
    y_test,
    y_pred_small,
    zero_division=0
)

f1_small = f1_score(
    y_test,
    y_pred_small,
    zero_division=0
)

print(f"Accuracy  : {accuracy_small:.4f}")
print(f"Precision : {precision_small:.4f}")
print(f"Recall    : {recall_small:.4f}")
print(f"F1 Score  : {f1_small:.4f}")


# ------------------------------------------------------------
# Validation 3: Feature-reduced model
# ------------------------------------------------------------

print("\n[3] Feature-Reduced Test")

REDUCED_FEATURES = [
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
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
    "HasExternalFormSubmit",
    "HasPasswordField",
    "Bank",
    "Pay",
    "Crypto",
]

reduced_indices = [
    FEATURES.index(feature)
    for feature in REDUCED_FEATURES
]

X_reduced = X[:, reduced_indices]

Xr_train, Xr_test, yr_train, yr_test = train_test_split(
    X_reduced,
    y,
    test_size=0.20,
    random_state=123,
    stratify=y
)

model_reduced = RandomForestClassifier(
    n_estimators=200,
    random_state=123,
    n_jobs=-1,
    class_weight="balanced"
)

model_reduced.fit(
    Xr_train,
    yr_train
)

yr_pred = model_reduced.predict(Xr_test)
yr_prob = model_reduced.predict_proba(Xr_test)[:, 1]

accuracy_reduced = accuracy_score(
    yr_test,
    yr_pred
)

precision_reduced = precision_score(
    yr_test,
    yr_pred,
    zero_division=0
)

recall_reduced = recall_score(
    yr_test,
    yr_pred,
    zero_division=0
)

f1_reduced = f1_score(
    yr_test,
    yr_pred,
    zero_division=0
)

roc_auc_reduced = roc_auc_score(
    yr_test,
    yr_prob
)

print(f"Features  : {len(REDUCED_FEATURES)}")
print(f"Accuracy  : {accuracy_reduced:.4f}")
print(f"Precision : {precision_reduced:.4f}")
print(f"Recall    : {recall_reduced:.4f}")
print(f"F1 Score  : {f1_reduced:.4f}")
print(f"ROC-AUC   : {roc_auc_reduced:.4f}")


# ============================================================
# FINAL CONFUSION MATRIX
# ============================================================

print("\n========================================")
print("CONFUSION MATRIX — REDUCED MODEL")
print("========================================")

print(
    confusion_matrix(
        yr_test,
        yr_pred
    )
)


# ============================================================
# SUMMARY
# ============================================================

print("\n========================================")
print("VALIDATION SUMMARY")
print("========================================")

print(
    f"Different split accuracy : "
    f"{accuracy:.4f}"
)

print(
    f"Reduced-data accuracy    : "
    f"{accuracy_small:.4f}"
)

print(
    f"Reduced-feature accuracy : "
    f"{accuracy_reduced:.4f}"
)

print("\nValidation complete.")
print("========================================")