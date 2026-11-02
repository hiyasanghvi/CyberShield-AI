from pathlib import Path
import csv
from collections import Counter


# ============================================================
# PATH
# ============================================================

INPUT_PATH = Path(
    "ml/datasets/url/processed/url_dataset_clean.csv"
)


if not INPUT_PATH.exists():
    raise FileNotFoundError(
        f"Dataset not found: {INPUT_PATH}"
    )


# ============================================================
# READ DATASET
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
    columns = reader.fieldnames


print("\n========================================")
print("URL FEATURE ANALYSIS")
print("========================================")

print(f"Rows    : {len(rows)}")
print(f"Columns : {len(columns)}")


# ============================================================
# FEATURE ANALYSIS
# ============================================================

print("\n----------------------------------------")
print("FEATURE DETAILS")
print("----------------------------------------")

for column in columns:

    values = [
        row[column].strip()
        for row in rows
    ]

    non_empty = [
        value
        for value in values
        if value != ""
    ]

    empty_count = len(values) - len(non_empty)

    unique_count = len(set(non_empty))

    # Try to determine whether values are numeric
    numeric_count = 0

    for value in non_empty:
        try:
            float(value)
            numeric_count += 1
        except ValueError:
            pass

    if numeric_count == len(non_empty) and non_empty:
        data_type = "NUMERIC"
    else:
        data_type = "TEXT/CATEGORICAL"

    print(
        f"{column:30} | "
        f"{data_type:18} | "
        f"unique={unique_count:8} | "
        f"empty={empty_count:6}"
    )


# ============================================================
# LABEL DISTRIBUTION
# ============================================================

print("\n----------------------------------------")
print("LABEL DISTRIBUTION")
print("----------------------------------------")

labels = Counter(
    row["label"]
    for row in rows
)

for label, count in sorted(labels.items()):
    percentage = (
        count / len(rows)
    ) * 100

    if label == "1":
        name = "LEGITIMATE"
    elif label == "0":
        name = "PHISHING"
    else:
        name = "UNKNOWN"

    print(
        f"{label} = {name:12} : "
        f"{count:8} ({percentage:.2f}%)"
    )


# ============================================================
# SAMPLE VALUES
# ============================================================

print("\n----------------------------------------")
print("SAMPLE VALUES")
print("----------------------------------------")

important_columns = [
    "URL",
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "NoOfSubDomain",
    "HasObfuscation",
    "IsHTTPS",
    "NoOfURLRedirect",
    "HasExternalFormSubmit",
    "HasPasswordField",
    "Bank",
    "Pay",
    "Crypto",
    "label",
]

for column in important_columns:

    if column not in columns:
        continue

    sample_values = []

    for row in rows[:5]:
        value = row[column]

        if value not in sample_values:
            sample_values.append(value)

    print(f"\n{column}:")
    for value in sample_values:
        print(f"  {value}")


print("\n========================================")
print("ANALYSIS COMPLETE")
print("========================================")