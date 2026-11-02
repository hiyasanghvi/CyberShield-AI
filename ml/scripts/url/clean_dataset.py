from pathlib import Path
import csv


# ============================================================
# PATHS
# ============================================================

INPUT_PATH = Path(
    "ml/datasets/url/raw/phiusiil_url_dataset.csv"
)

OUTPUT_DIR = Path(
    "ml/datasets/url/processed"
)

OUTPUT_PATH = OUTPUT_DIR / "url_dataset_clean.csv"


# ============================================================
# CHECK INPUT
# ============================================================

if not INPUT_PATH.exists():
    raise FileNotFoundError(
        f"Dataset not found: {INPUT_PATH}"
    )

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# READ + CLEAN
# ============================================================

rows = []

seen_urls = set()

total_rows = 0
duplicate_rows = 0
invalid_rows = 0


with open(
    INPUT_PATH,
    "r",
    encoding="utf-8",
    errors="ignore",
    newline=""
) as file:

    reader = csv.DictReader(file)

    fieldnames = reader.fieldnames

    if not fieldnames:
        raise ValueError(
            "Dataset has no columns."
        )

    required_columns = {
        "URL",
        "label",
    }

    missing_columns = (
        required_columns
        - set(fieldnames)
    )

    if missing_columns:
        raise ValueError(
            f"Missing columns: {missing_columns}"
        )

    for row in reader:

        total_rows += 1

        url = row["URL"].strip()
        label = row["label"].strip()

        # ----------------------------------------
        # Invalid URL / label
        # ----------------------------------------

        if not url or label not in {"0", "1"}:
            invalid_rows += 1
            continue

        # ----------------------------------------
        # Duplicate URL
        # ----------------------------------------

        url_key = url.lower()

        if url_key in seen_urls:
            duplicate_rows += 1
            continue

        seen_urls.add(url_key)

        # ----------------------------------------
        # Keep cleaned row
        # ----------------------------------------

        cleaned_row = {
            column: row[column].strip()
            for column in fieldnames
        }

        rows.append(cleaned_row)


# ============================================================
# WRITE CLEAN DATASET
# ============================================================

with open(
    OUTPUT_PATH,
    "w",
    encoding="utf-8",
    newline=""
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=fieldnames
    )

    writer.writeheader()

    writer.writerows(rows)


# ============================================================
# LABEL COUNTS
# ============================================================

legitimate = sum(
    1
    for row in rows
    if row["label"] == "1"
)

phishing = sum(
    1
    for row in rows
    if row["label"] == "0"
)


# ============================================================
# SUMMARY
# ============================================================

print("\n========================================")
print("URL DATASET CLEANING COMPLETE")
print("========================================")

print(f"Original rows      : {total_rows}")
print(f"Duplicate URLs     : {duplicate_rows}")
print(f"Invalid rows       : {invalid_rows}")
print(f"Final rows         : {len(rows)}")

print("\nLabel distribution:")
print(f"Legitimate (1)     : {legitimate}")
print(f"Phishing (0)       : {phishing}")

print("\nOutput:")
print(OUTPUT_PATH)

print("========================================")