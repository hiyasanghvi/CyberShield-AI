import csv
import json
import math
import random
import re
from collections import Counter
from pathlib import Path
csv.field_size_limit(10_000_000)
PROJECT_ROOT = Path(__file__).resolve().parents[3]

DATASET = PROJECT_ROOT / "ml" / "datasets" / "email" / "processed" / "email_dataset.csv"

MODEL_DIR = PROJECT_ROOT / "ml" / "models" / "email"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

MODEL_FILE = MODEL_DIR / "email_naive_bayes.json"
METADATA_FILE = MODEL_DIR / "email_metadata.json"

TOKEN_PATTERN = re.compile(r"[a-zA-Z0-9]+")

MAX_VOCAB = 12000
MIN_DF = 2


def tokenize(text):
    return TOKEN_PATTERN.findall(text.lower())


def load_dataset():
    rows = []

    with open(DATASET, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            text = f"{row['subject']} {row['body']}"

            rows.append({
                "text": text,
                "label": 1 if row["label"] == "SPAM" else 0,
                "contains_url": int(row["contains_url"]),
                "url_count": int(row["url_count"]),
                "has_attachment": int(row["has_attachment"]),
            })

    return rows


def split_dataset(rows):
    random.seed(42)
    random.shuffle(rows)

    split = int(len(rows) * 0.8)

    return rows[:split], rows[split:]


def build_vocabulary(rows):
    document_frequency = Counter()

    for row in rows:
        tokens = set(tokenize(row["text"]))

        for token in tokens:
            document_frequency[token] += 1

    valid = [
        (token, count)
        for token, count in document_frequency.items()
        if count >= MIN_DF
    ]

    valid.sort(key=lambda x: (-x[1], x[0]))

    return [token for token, _ in valid[:MAX_VOCAB]]


def train(train_rows, vocabulary):
    vocab_set = set(vocabulary)

    word_counts = {
        0: Counter(),
        1: Counter()
    }

    total_words = {
        0: 0,
        1: 0
    }

    class_counts = Counter()

    for row in train_rows:
        label = row["label"]
        class_counts[label] += 1

        tokens = tokenize(row["text"])

        for token in tokens:
            if token in vocab_set:
                word_counts[label][token] += 1
                total_words[label] += 1

    vocab_size = len(vocabulary)

    log_prob = {
        "0": {},
        "1": {}
    }

    for label in [0, 1]:
        denominator = total_words[label] + vocab_size

        for token in vocabulary:
            probability = (
                word_counts[label][token] + 1
            ) / denominator

            log_prob[str(label)][token] = math.log(probability)

    total_docs = len(train_rows)

    log_prior = {
        "0": math.log(class_counts[0] / total_docs),
        "1": math.log(class_counts[1] / total_docs)
    }

    return {
        "vocabulary": vocabulary,
        "log_prob": log_prob,
        "log_prior": log_prior
    }


def predict(text, model):
    tokens = tokenize(text)

    scores = {}

    for label in ["0", "1"]:
        score = model["log_prior"][label]

        for token in tokens:
            if token in model["log_prob"][label]:
                score += model["log_prob"][label][token]

        scores[label] = score

    max_score = max(scores.values())

    p0 = math.exp(scores["0"] - max_score)
    p1 = math.exp(scores["1"] - max_score)

    total = p0 + p1

    ham_probability = p0 / total
    spam_probability = p1 / total

    prediction = 1 if spam_probability >= 0.5 else 0

    return prediction, spam_probability, ham_probability


def evaluate(test_rows, model):
    tp = tn = fp = fn = 0

    for row in test_rows:
        prediction, _, _ = predict(row["text"], model)
        actual = row["label"]

        if prediction == 1 and actual == 1:
            tp += 1
        elif prediction == 0 and actual == 0:
            tn += 1
        elif prediction == 1 and actual == 0:
            fp += 1
        elif prediction == 0 and actual == 1:
            fn += 1

    total = tp + tn + fp + fn

    accuracy = (tp + tn) / total if total else 0

    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "confusion_matrix": [
            [tn, fp],
            [fn, tp]
        ]
    }


def main():
    print("Loading email dataset...")

    rows = load_dataset()

    print(f"Total emails: {len(rows)}")

    train_rows, test_rows = split_dataset(rows)

    print(f"Training: {len(train_rows)}")
    print(f"Testing : {len(test_rows)}")

    print("Building vocabulary...")

    vocabulary = build_vocabulary(train_rows)

    print(f"Vocabulary size: {len(vocabulary)}")

    print("Training Multinomial Naive Bayes...")

    model = train(train_rows, vocabulary)

    metrics = evaluate(test_rows, model)

    model["model_type"] = "Multinomial Naive Bayes"
    model["version"] = "1.0"

    with open(MODEL_FILE, "w", encoding="utf-8") as f:
        json.dump(model, f)

    metadata = {
        "model": "Multinomial Naive Bayes",
        "dataset": "Apache SpamAssassin Public Corpus",
        "total_samples": len(rows),
        "training_samples": len(train_rows),
        "testing_samples": len(test_rows),
        "vocabulary_size": len(vocabulary),
        "metrics": metrics
    }

    with open(METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)

    print("\n===== EMAIL MODEL RESULTS =====")
    print(f"Accuracy : {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall   : {metrics['recall']:.4f}")
    print(f"F1 Score : {metrics['f1']:.4f}")

    print("\nConfusion Matrix:")
    print(metrics["confusion_matrix"])

    print(f"\nModel saved: {MODEL_FILE}")


if __name__ == "__main__":
    main()