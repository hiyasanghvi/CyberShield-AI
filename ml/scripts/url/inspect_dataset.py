from pathlib import Path
import csv

dataset_path = Path("ml/datasets/url/raw/phiusiil_url_dataset.csv")

if not dataset_path.exists():
    raise FileNotFoundError(
        f"Dataset not found: {dataset_path}"
    )

with open(
    dataset_path,
    "r",
    encoding="utf-8",
    errors="ignore",
    newline=""
) as file:

    reader = csv.reader(file)

    header = next(reader)

    print("\n===== DATASET INSPECTION =====\n")

    print("Number of columns:", len(header))

    print("\nColumns:")
    for i, column in enumerate(header):
        print(f"{i}: {column}")

    row_count = 0
    first_rows = []

    for row in reader:
        row_count += 1

        if len(first_rows) < 5:
            first_rows.append(row)

print("\nNumber of rows:", row_count)

print("\nFirst 5 rows:")
for row in first_rows:
    print(row)

print("\n===== INSPECTION COMPLETE =====")