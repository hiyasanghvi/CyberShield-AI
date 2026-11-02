from pathlib import Path
import csv
from collections import defaultdict

import numpy as np

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
    "ml/datasets/url/processed/url_dataset_clean.csv"
)


# ============================================================
# FEATURES
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
# LOAD DATA
# ============================================================

with open(
    INPUT_PATH,
    "r",
    encoding="utf-8",
    errors="ignore",
    newline=""
) as file:

    reader = csv.DictReader(file)
    rows = list(reader)


# ============================================================
# GROUP ROWS BY DOMAIN
# ============================================================

domain_groups = defaultdict(list)

for row in rows:

    domain = row["Domain"].strip().lower()

    if not domain:
        continue

    domain_groups[domain].append(row)


print("\n========================================")
print("UNSEEN-DOMAIN VALIDATION")
print("========================================")

print(f"Total rows    : {len(rows)}")
print(f"Unique domains: {len(domain_groups)}")


# ============================================================
# SORT DOMAINS DETERMINISTICALLY
# ============================================================

domains = sorted(domain_groups.keys())


# ============================================================
# DOMAIN SPLIT
# 80% DOMAINS -> TRAIN
# 20% DOMAINS -> TEST
# ============================================================

split_index = int(
    len(domains) * 0.80
)

train_domains = set(
    domains[:split_index]
)

test_domains = set(
    domains[split_index:]
)


train_rows = []
test_rows = []

for domain, domain_rows in domain_groups.items():

    if domain in train_domains:
        train_rows.extend(domain_rows)

    else:
        test_rows.extend(domain_rows)


print("\nDomain split:")
print(
    f"Training domains : {len(train_domains)}"
)

print(
    f"Testing domains  : {len(test_domains)}"
)

print(
    f"Training samples : {len(train_rows)}"
)

print(
    f"Testing samples  : {len(test_rows)}"
)


# ============================================================
# CREATE X / Y
# ============================================================

def create_arrays(data):

    X = np.array(
        [
            [
                float(row[feature])
                for feature in FEATURES
            ]
            for row in data
        ],
        dtype=np.float64
    )

    y = np.array(
        [
            int(row["label"])
            for row in data
        ],
        dtype=np.int64
    )

    return X, y


X_train, y_train = create_arrays(
    train_rows
)

X_test, y_test = create_arrays(
    test_rows
)


# ============================================================
# MODEL
# ============================================================

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(
    X_train,
    y_train
)

print("Training complete.")


# ============================================================
# PREDICTION
# ============================================================

y_pred = model.predict(
    X_test
)

y_prob = model.predict_proba(
    X_test
)[:, 1]


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
    y_prob
)

cm = confusion_matrix(
    y_test,
    y_pred
)


# ============================================================
# RESULTS
# ============================================================

print("\n========================================")
print("UNSEEN-DOMAIN RESULTS")
print("========================================")

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")
print(f"ROC-AUC   : {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(cm)


# ============================================================
# DOMAIN OVERLAP CHECK
# ============================================================

overlap = train_domains.intersection(
    test_domains
)

print("\n========================================")
print("DOMAIN OVERLAP CHECK")
print("========================================")

print(
    f"Overlapping domains: {len(overlap)}"
)

if len(overlap) == 0:
    print(
        "PASS: Test domains are completely unseen during training."
    )
else:
    print(
        "WARNING: Domain overlap detected."
    )


print("\n========================================")
print("VALIDATION COMPLETE")
print("========================================")