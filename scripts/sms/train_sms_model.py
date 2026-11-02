import csv
import json
from pathlib import Path

import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[3]

DATASET_PATH = (
    PROJECT_ROOT
    / "ml"
    / "datasets"
    / "sms"
    / "raw"
    / "SMSSpamCollection"
)

MODEL_DIR = (
    PROJECT_ROOT
    / "ml"
    / "models"
    / "sms"
)

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True
)

MODEL_PATH = MODEL_DIR / "sms_tfidf_logistic.joblib"
METADATA_PATH = MODEL_DIR / "sms_metadata.json"


# ---------------------------------------------------------
# Load dataset
# ---------------------------------------------------------

texts = []
labels = []

with open(
    DATASET_PATH,
    "r",
    encoding="utf-8",
    errors="replace",
) as file:

    reader = csv.reader(
        file,
        delimiter="\t"
    )

    for row in reader:

        if len(row) < 2:
            continue

        label = row[0].strip().lower()
        text = row[1].strip()

        if label not in {"ham", "spam"}:
            continue

        texts.append(text)
        labels.append(label)


print("Dataset loaded")
print("Total messages:", len(texts))
print("Ham:", labels.count("ham"))
print("Spam:", labels.count("spam"))


# ---------------------------------------------------------
# Train / test split
# ---------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    texts,
    labels,
    test_size=0.20,
    random_state=42,
    stratify=labels,
)


# ---------------------------------------------------------
# TF-IDF + Logistic Regression
# ---------------------------------------------------------

model = Pipeline(
    [
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                strip_accents="unicode",
                ngram_range=(1, 2),
                min_df=2,
                max_df=0.98,
                sublinear_tf=True,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                random_state=42,
            ),
        ),
    ]
)


print("\nTraining model...")

model.fit(
    X_train,
    y_train
)


# ---------------------------------------------------------
# Evaluation
# ---------------------------------------------------------

predictions = model.predict(X_test)

probabilities = model.predict_proba(X_test)

spam_index = list(
    model.classes_
).index("spam")

spam_probabilities = probabilities[:, spam_index]


accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    pos_label="spam"
)

recall = recall_score(
    y_test,
    predictions,
    pos_label="spam"
)

f1 = f1_score(
    y_test,
    predictions,
    pos_label="spam"
)

roc_auc = roc_auc_score(
    [1 if label == "spam" else 0 for label in y_test],
    spam_probabilities
)


print("\n==============================")
print("SMS MODEL RESULTS")
print("==============================")

print(f"Accuracy : {accuracy:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")

print("\nConfusion Matrix:")
print(
    confusion_matrix(
        y_test,
        predictions,
        labels=["ham", "spam"]
    )
)

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        digits=4
    )
)


# ---------------------------------------------------------
# Save model
# ---------------------------------------------------------

joblib.dump(
    model,
    MODEL_PATH
)


metadata = {
    "model_type": "TF-IDF + Logistic Regression",
    "dataset": "UCI SMS Spam Collection",
    "classes": ["ham", "spam"],
    "test_size": 0.20,
    "random_state": 42,
    "metrics": {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
    },
}


with open(
    METADATA_PATH,
    "w",
    encoding="utf-8",
) as file:

    json.dump(
        metadata,
        file,
        indent=4
    )


print("\nModel saved:")
print(MODEL_PATH)

print("\nMetadata saved:")
print(METADATA_PATH)