from pathlib import Path
import csv
import sys


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[3]

BACKEND_DIR = PROJECT_ROOT / "backend"

sys.path.insert(
    0,
    str(BACKEND_DIR)
)


# ============================================================
# IMPORT FEATURE EXTRACTOR
# ============================================================

from app.ml.url_detection.feature_extractor import (
    extract_url_features
)


# ============================================================
# DATASET PATH
# ============================================================

DATASET_PATH = (
    PROJECT_ROOT
    / "ml"
    / "datasets"
    / "url"
    / "processed"
    / "url_dataset_clean.csv"
)


# ============================================================
# FINAL 24 FEATURES
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
# CHECK DATASET
# ============================================================

if not DATASET_PATH.exists():

    raise FileNotFoundError(
        f"Dataset not found:\n{DATASET_PATH}"
    )


# ============================================================
# LOAD SAMPLE DATA
# ============================================================

samples = []

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

        if url:

            samples.append(row)

        if len(samples) >= 20:

            break


# ============================================================
# VALIDATION
# ============================================================

total_comparisons = 0
matching_values = 0
different_values = 0


print("\n========================================")
print("FEATURE EXTRACTOR VALIDATION")
print("========================================")

print(
    f"Dataset: {DATASET_PATH}"
)

print(
    f"Samples: {len(samples)}"
)


# ============================================================
# COMPARE FEATURES
# ============================================================

for index, row in enumerate(
    samples,
    start=1
):

    url = row["URL"]

    extracted = extract_url_features(
        url
    )

    print("\n----------------------------------------")
    print(f"Sample {index}")
    print(f"URL: {url}")
    print("----------------------------------------")

    for feature in FEATURES:

        dataset_value = float(
            row[feature]
        )

        extracted_value = float(
            extracted[feature]
        )

        total_comparisons += 1

        # ----------------------------------------------------
        # Floating-point comparison
        # ----------------------------------------------------

        if abs(
            dataset_value - extracted_value
        ) < 0.000001:

            matching_values += 1

        else:

            different_values += 1

            print(
                f"{feature:30} "
                f"Dataset={dataset_value:<12} "
                f"Our={extracted_value}"
            )


# ============================================================
# SUMMARY
# ============================================================

match_percentage = (
    matching_values / total_comparisons * 100
    if total_comparisons > 0
    else 0
)


print("\n========================================")
print("VALIDATION SUMMARY")
print("========================================")

print(
    f"Samples tested      : {len(samples)}"
)

print(
    f"Features/sample     : {len(FEATURES)}"
)

print(
    f"Total comparisons   : {total_comparisons}"
)

print(
    f"Matching values     : {matching_values}"
)

print(
    f"Different values    : {different_values}"
)

print(
    f"Match percentage    : {match_percentage:.2f}%"
)

print("========================================")