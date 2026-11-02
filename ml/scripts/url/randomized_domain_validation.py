from pathlib import Path
import csv
import sys

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)


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
# DOMAIN EXTRACTION
# ============================================================

def get_domain(url: str) -> str:

    from urllib.parse import urlparse

    parsed = urlparse(
        url if "://" in url else "http://" + url
    )

    domain = parsed.netloc

    domain = domain.split("@")[-1]
    domain = domain.split(":")[0]

    return domain.lower()


# ============================================================
# LOAD DATA
# ============================================================

X = []
y = []
groups = []

print("\n========================================")
print("LOADING URL DATASET")
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
        groups.append(get_domain(url))


print(f"Samples        : {len(X)}")
print(f"Unique domains : {len(set(groups))}")
print(f"Features       : {len(FEATURES)}")


# ============================================================
# RANDOMIZED GROUP SPLIT
# ============================================================

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)


train_indices, test_indices = next(
    splitter.split(
        X,
        y,
        groups=groups,
    )
)


# ============================================================
# BUILD TRAIN / TEST SETS
# ============================================================

X_train = [X[i] for i in train_indices]
X_test = [X[i] for i in test_indices]

y_train = [y[i] for i in train_indices]
y_test = [y[i] for i in test_indices]

train_domains = {
    groups[i]
    for i in train_indices
}

test_domains = {
    groups[i]
    for i in test_indices
}


# ============================================================
# CHECK DOMAIN LEAKAGE
# ============================================================

overlap = train_domains.intersection(
    test_domains
)


print("\n========================================")
print("RANDOMIZED DOMAIN SPLIT")
print("========================================")

print(f"Training domains : {len(train_domains)}")
print(f"Testing domains  : {len(test_domains)}")

print(f"Training samples : {len(X_train)}")
print(f"Testing samples  : {len(X_test)}")

print(f"Domain overlap   : {len(overlap)}")


if overlap:
    raise RuntimeError(
        "Domain leakage detected!"
    )


# ============================================================
# TRAIN MODEL
# ============================================================

print("\n========================================")
print("TRAINING RANDOM FOREST")
print("========================================")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1,
)

model.fit(
    X_train,
    y_train,
)


# ============================================================
# PREDICTION
# ============================================================

y_pred = model.predict(X_test)

y_prob = model.predict_proba(
    X_test
)[:, 1]


# ============================================================
# METRICS
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred,
)

precision = precision_score(
    y_test,
    y_pred,
)

recall = recall_score(
    y_test,
    y_pred,
)

f1 = f1_score(
    y_test,
    y_pred,
)

roc_auc = roc_auc_score(
    y_test,
    y_prob,
)

cm = confusion_matrix(
    y_test,
    y_pred,
)


# ============================================================
# RESULTS
# ============================================================

print("\n========================================")
print("RANDOMIZED UNSEEN-DOMAIN RESULTS")
print("========================================")

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")
print(f"ROC-AUC   : {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(cm)


# ============================================================
# VALIDATION STATUS
# ============================================================

print("\n========================================")
print("VALIDATION STATUS")
print("========================================")

if len(overlap) == 0:
    print("PASS: Zero domain overlap.")
else:
    print("FAIL: Domain overlap detected.")

print("\n========================================")
print("RANDOMIZED DOMAIN VALIDATION COMPLETED")
print("========================================")