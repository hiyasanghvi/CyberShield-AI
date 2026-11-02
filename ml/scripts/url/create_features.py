from pathlib import Path
import csv


# ============================================================
# PATHS
# ============================================================

INPUT_PATH = Path(
    "ml/datasets/url/processed/url_dataset_clean.csv"
)

OUTPUT_DIR = Path(
    "ml/datasets/url/processed"
)

OUTPUT_PATH = OUTPUT_DIR / "url_features.csv"


# ============================================================
# SELECTED FEATURES
# ============================================================

FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "URLSimilarityIndex",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb",
    "TLDLength",
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
    "DomainTitleMatchScore",
    "URLTitleMatchScore",
    "HasFavicon",
    "Robots",
    "IsResponsive",
    "NoOfURLRedirect",
    "NoOfSelfRedirect",
    "HasDescription",
    "NoOfPopup",
    "NoOfiFrame",
    "HasExternalFormSubmit",
    "HasSocialNet",
    "HasSubmitButton",
    "HasHiddenFields",
    "HasPasswordField",
    "Bank",
    "Pay",
    "Crypto",
    "HasCopyrightInfo",
    "NoOfImage",
    "NoOfCSS",
    "NoOfJS",
    "NoOfSelfRef",
    "NoOfEmptyRef",
    "NoOfExternalRef",
]

TARGET = "label"


# ============================================================
# CHECK INPUT
# ============================================================

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

    columns = reader.fieldnames

    if columns is None:
        raise ValueError("Dataset has no columns.")

    required_columns = set(FEATURES + [TARGET])

    missing_columns = (
        required_columns - set(columns)
    )

    if missing_columns:
        raise ValueError(
            f"Missing columns: {missing_columns}"
        )

    rows = list(reader)


# ============================================================
# CONVERT FEATURES TO NUMERIC
# ============================================================

processed_rows = []

invalid_rows = 0

for row in rows:

    new_row = {}

    try:

        for feature in FEATURES:
            new_row[feature] = float(
                row[feature]
            )

        new_row[TARGET] = int(
            row[TARGET]
        )

        processed_rows.append(new_row)

    except (ValueError, TypeError):
        invalid_rows += 1


# ============================================================
# WRITE FEATURE DATASET
# ============================================================

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

output_columns = FEATURES + [TARGET]

with open(
    OUTPUT_PATH,
    "w",
    encoding="utf-8",
    newline=""
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=output_columns
    )

    writer.writeheader()

    writer.writerows(processed_rows)


# ============================================================
# SUMMARY
# ============================================================

print("\n========================================")
print("URL FEATURE DATASET CREATED")
print("========================================")

print(f"Input rows          : {len(rows)}")
print(f"Invalid rows        : {invalid_rows}")
print(f"Final rows          : {len(processed_rows)}")
print(f"Features            : {len(FEATURES)}")
print(f"Target              : {TARGET}")

print("\nOutput:")
print(OUTPUT_PATH)

print("\nSelected features:")
for index, feature in enumerate(FEATURES, start=1):
    print(f"{index:2}. {feature}")

print("========================================")