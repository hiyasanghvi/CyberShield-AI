from pathlib import Path
import csv
import numpy as np

from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.ensemble import RandomForestClassifier


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


# ============================================================
# FINAL REDUCED FEATURE SET
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
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
    "HasExternalFormSubmit",
    "HasPasswordField",
    "Bank",
    "Pay",
    "Crypto",
]


# ============================================================
# CREATE X AND Y
# ============================================================

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


print("\n========================================")
print("5-FOLD CROSS-VALIDATION")
print("========================================")

print(f"Samples  : {len(X)}")
print(f"Features : {len(FEATURES)}")


# ============================================================
# MODEL
# ============================================================

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)


# ============================================================
# STRATIFIED 5-FOLD
# ============================================================

cv = StratifiedKFold(
    n_splits=5,
    shuffle=True,
    random_state=42
)


scoring = [
    "accuracy",
    "precision",
    "recall",
    "f1",
    "roc_auc",
]


print("\nRunning 5 folds...")

results = cross_validate(
    model,
    X,
    y,
    cv=cv,
    scoring=scoring,
    n_jobs=1,
    return_train_score=False
)


# ============================================================
# RESULTS
# ============================================================

print("\n========================================")
print("CROSS-VALIDATION RESULTS")
print("========================================")

for metric in scoring:

    scores = results[
        f"test_{metric}"
    ]

    print(
        f"\n{metric.upper()}"
    )

    for fold, score in enumerate(
        scores,
        start=1
    ):
        print(
            f"Fold {fold}: {score:.4f}"
        )

    print(
        f"Mean    : {scores.mean():.4f}"
    )

    print(
        f"Std     : {scores.std():.4f}"
    )


# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n========================================")
print("FINAL CROSS-VALIDATION SUMMARY")
print("========================================")

for metric in scoring:

    scores = results[
        f"test_{metric}"
    ]

    print(
        f"{metric.upper():10} "
        f"{scores.mean():.4f} "
        f"+/- {scores.std():.4f}"
    )


print("\n========================================")
print("CROSS-VALIDATION COMPLETE")
print("========================================")