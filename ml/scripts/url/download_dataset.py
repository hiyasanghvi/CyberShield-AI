from ucimlrepo import fetch_ucirepo
import pandas as pd
from pathlib import Path

# Load PhiUSIIL dataset
dataset = fetch_ucirepo(id=967)

X = dataset.data.features
y = dataset.data.targets

df = pd.concat([X, y], axis=1)

# Create output directory
output_dir = Path("ml/datasets/url/raw")
output_dir.mkdir(parents=True, exist_ok=True)

output_path = output_dir / "phiusiil_url_dataset.csv"

df.to_csv(output_path, index=False)

print("Dataset downloaded successfully!")
print(f"Shape: {df.shape}")
print("\nColumns:")
print(df.columns.tolist())
print("\nLabel distribution:")
print(df.iloc[:, -1].value_counts())
print(f"\nSaved to: {output_path}")