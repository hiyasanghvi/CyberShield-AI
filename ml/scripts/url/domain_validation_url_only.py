from pathlib import Path
import csv
import sys

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
# EXTRACT DOMAIN
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
# LOAD DATA GROUPED BY DOMAIN
# ============================================================

domain_rows = {}

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

        domain = get_domain(url)

        if domain not in domain_rows:
            domain_rows[domain] = []

        domain_rows[domain].append(row)


print(f"Total rows    : {sum(len(v) for v in domain_rows.values())}")
print(f"Unique domains: {len(domain_rows)}")


# ============================================================
# SORT DOMAINS
# ============================================================

domains = sorted(domain_rows.keys())


# ============================================================
# 80/20 DOMAIN SPLIT
# ============================================================

split_index = int(len(domains) * 0.80)

train_domains = domains[:split_index]
test_domains = domains[split_index:]


train_domain_set = set(train_domains)
test_domain_set = set(test_domains)


print("\n========================================")
print("DOMAIN SPLIT")
print("========================================")

print(f"Training domains : {len(train_domains)}")
print(f"Testing domains  : {len(test_domains)}")


# ============================================================
# VERIFY NO DOMAIN OVERLAP
# ============================================================

overlap = train_domain_set.intersection(
    test_domain_set
)

print(f"Domain overlap   : {len(overlap)}")

if overlap:
    raise RuntimeError(
        "Domain leakage detected!"
    )


# ============================================================
# BUILD TRAIN / TEST FEATURES
# ============================================================

X_train = []
y_train = []

X_test = []
y_test = []


print("\n========================================")
print("BUILDING FEATURES")
print("========================================")


for domain in train_domains:

    for row in domain_rows[domain]:

        url = row["URL"].strip()

        extracted = extract_url_features(url)

        feature_vector = [
            float(extracted[feature])
            for feature in FEATURES
        ]

        X_train.append(feature_vector)
        y_train.append(int(row["label"]))


for domain in test_domains:

    for row in domain_rows[domain]:

        url = row["URL"].strip()

        extracted = extract_url_features(url)

        feature_vector = [
            float(extracted[feature])
            for feature in FEATURES
        ]

        X_test.append(feature_vector)
        y_test.append(int(row["label"]))


print(f"Training samples : {len(X_train)}")
print(f"Testing samples  : {len(X_test)}")


# ============================================================
# TRAIN MODEL
# ============================================================

print("\n========================================")
print("TRAINING MODEL")
print("========================================")


model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced",
    n_jobs=-1,
)

model.fit(
    X_train,
    y_train
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
    y_pred
)

precision = precision_score(
    y_test,
    y_pred
)

recall = recall_score(
    y_test,
    y_pred
)

f1 = f1_score(
    y_test,
    y_pred
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
print("UNSEEN-DOMAIN VALIDATION RESULTS")
print("========================================")

print(f"Accuracy  : {accuracy:.4f}")
print(f"Precision : {precision:.4f}")
print(f"Recall    : {recall:.4f}")
print(f"F1 Score  : {f1:.4f}")
print(f"ROC-AUC   : {roc_auc:.4f}")


print("\nConfusion Matrix:")
print(cm)


# ============================================================
# FINAL CHECK
# ============================================================

print("\n========================================")
print("VALIDATION CHECK")
print("========================================")

if len(overlap) == 0:
    print("PASS: No domain overlap.")
else:
    print("FAIL: Domain overlap detected.")


print("\n========================================")
print("UNSEEN-DOMAIN VALIDATION COMPLETED")
print("========================================")