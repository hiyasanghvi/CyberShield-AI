import csv
import json
import math
import random
import re
from collections import Counter
from pathlib import Path

import numpy as np


# =========================================================
# PATHS
# =========================================================

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

MODEL_PATH = MODEL_DIR / "sms_tfidf_logistic.json"
METADATA_PATH = MODEL_DIR / "sms_metadata.json"


# =========================================================
# TEXT TOKENIZATION
# =========================================================

def tokenize(text):
    text = text.lower()

    tokens = re.findall(
        r"[a-z0-9]+",
        text
    )

    # Add bigrams
    bigrams = [
        tokens[i] + "_" + tokens[i + 1]
        for i in range(len(tokens) - 1)
    ]

    return tokens + bigrams


# =========================================================
# LOAD DATASET
# =========================================================

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

        labels.append(
            1 if label == "spam" else 0
        )


print("Dataset loaded")
print("Total messages:", len(texts))
print("Ham:", labels.count(0))
print("Spam:", labels.count(1))


# =========================================================
# SHUFFLE + STRATIFIED SPLIT
# =========================================================

random.seed(42)

spam_indices = [
    i for i, label in enumerate(labels)
    if label == 1
]

ham_indices = [
    i for i, label in enumerate(labels)
    if label == 0
]

random.shuffle(spam_indices)
random.shuffle(ham_indices)

spam_test_count = int(
    len(spam_indices) * 0.20
)

ham_test_count = int(
    len(ham_indices) * 0.20
)

test_indices = (
    spam_indices[:spam_test_count]
    + ham_indices[:ham_test_count]
)

train_indices = (
    spam_indices[spam_test_count:]
    + ham_indices[ham_test_count:]
)

random.shuffle(train_indices)
random.shuffle(test_indices)

X_train_text = [
    texts[i]
    for i in train_indices
]

y_train = np.array(
    [labels[i] for i in train_indices],
    dtype=np.float64
)

X_test_text = [
    texts[i]
    for i in test_indices
]

y_test = np.array(
    [labels[i] for i in test_indices],
    dtype=np.float64
)


print("\nTraining messages:", len(X_train_text))
print("Testing messages :", len(X_test_text))


# =========================================================
# BUILD VOCABULARY
# =========================================================

document_frequency = Counter()

for text in X_train_text:

    unique_tokens = set(
        tokenize(text)
    )

    for token in unique_tokens:
        document_frequency[token] += 1


MIN_DF = 2

vocabulary = {}

for token, count in document_frequency.items():

    if count >= MIN_DF:

        vocabulary[token] = len(vocabulary)


print("\nVocabulary size:", len(vocabulary))


# =========================================================
# IDF
# =========================================================

N = len(X_train_text)

idf = np.zeros(
    len(vocabulary),
    dtype=np.float64
)

for token, index in vocabulary.items():

    df = document_frequency[token]

    idf[index] = math.log(
        (N + 1) / (df + 1)
    ) + 1


# =========================================================
# TF-IDF TRANSFORMATION
# =========================================================

def transform_texts(text_list):

    matrix = np.zeros(
        (len(text_list), len(vocabulary)),
        dtype=np.float64
    )

    for row_index, text in enumerate(text_list):

        tokens = tokenize(text)

        counts = Counter(tokens)

        total_tokens = len(tokens)

        if total_tokens == 0:
            continue

        for token, count in counts.items():

            if token not in vocabulary:
                continue

            column_index = vocabulary[token]

            tf = count / total_tokens

            matrix[row_index, column_index] = (
                tf * idf[column_index]
            )

        # L2 normalization
        norm = np.linalg.norm(
            matrix[row_index]
        )

        if norm > 0:

            matrix[row_index] /= norm

    return matrix


print("\nCreating TF-IDF matrices...")

X_train = transform_texts(
    X_train_text
)

X_test = transform_texts(
    X_test_text
)


print(
    "Training matrix:",
    X_train.shape
)

print(
    "Testing matrix:",
    X_test.shape
)


# =========================================================
# LOGISTIC REGRESSION
# =========================================================

def sigmoid(z):

    z = np.clip(
        z,
        -50,
        50
    )

    return 1.0 / (
        1.0 + np.exp(-z)
    )


weights = np.zeros(
    X_train.shape[1],
    dtype=np.float64
)

bias = 0.0

learning_rate = 0.15
epochs = 400
regularization = 0.0001

# ---------------------------------------------------------
# Class weights
# ---------------------------------------------------------
# Give more importance to SPAM because the dataset
# contains far fewer spam messages than ham messages.

positive_count = np.sum(y_train == 1)
negative_count = np.sum(y_train == 0)
total_count = len(y_train)

spam_weight = (
    total_count /
    (2.0 * positive_count)
)

ham_weight = (
    total_count /
    (2.0 * negative_count)
)

sample_weights = np.where(
    y_train == 1,
    spam_weight,
    ham_weight
)

print("\nClass weights:")
print("HAM :", ham_weight)
print("SPAM:", spam_weight)


print("\nTraining Logistic Regression...")

for epoch in range(epochs):

    logits = (
        X_train @ weights
        + bias
    )

    probabilities = sigmoid(
        logits
    )

    error = (
    probabilities - y_train)
    weighted_error = (
    sample_weights * error)
    gradient_weights = (
    (X_train.T @ weighted_error)
    / len(y_train))
    gradient_weights += (
    regularization * weights)
    gradient_bias = (
    np.mean(weighted_error))


    weights -= (
        learning_rate
        * gradient_weights
    )

    bias -= (
        learning_rate
        * gradient_bias
    )

    if (epoch + 1) % 50 == 0:

        loss = -np.mean(
            y_train * np.log(
                probabilities + 1e-9
            )
            +
            (1 - y_train)
            * np.log(
                1 - probabilities + 1e-9
            )
        )

        print(
            f"Epoch {epoch + 1:3d} "
            f"Loss: {loss:.5f}"
        )


# =========================================================
# PREDICTION
# =========================================================

test_probabilities = sigmoid(
    X_test @ weights + bias
)

test_predictions = (
    test_probabilities >= 0.5
).astype(int)


# =========================================================
# METRICS
# =========================================================

tp = int(
    np.sum(
        (test_predictions == 1)
        & (y_test == 1)
    )
)

tn = int(
    np.sum(
        (test_predictions == 0)
        & (y_test == 0)
    )
)

fp = int(
    np.sum(
        (test_predictions == 1)
        & (y_test == 0)
    )
)

fn = int(
    np.sum(
        (test_predictions == 0)
        & (y_test == 1)
    )
)


accuracy = (
    (tp + tn)
    / len(y_test)
)

precision = (
    tp / (tp + fp)
    if (tp + fp) > 0
    else 0
)

recall = (
    tp / (tp + fn)
    if (tp + fn) > 0
    else 0
)

f1 = (
    2 * precision * recall
    / (precision + recall)
    if (precision + recall) > 0
    else 0
)


# =========================================================
# ROC-AUC
# =========================================================

def calculate_auc(y_true, scores):

    positives = [
        score
        for label, score
        in zip(y_true, scores)
        if label == 1
    ]

    negatives = [
        score
        for label, score
        in zip(y_true, scores)
        if label == 0
    ]

    if not positives or not negatives:
        return 0.0

    # Mann-Whitney formulation
    comparisons = 0.0

    for positive in positives:

        for negative in negatives:

            if positive > negative:
                comparisons += 1

            elif positive == negative:
                comparisons += 0.5

    return comparisons / (
        len(positives)
        * len(negatives)
    )


roc_auc = calculate_auc(
    y_test.astype(int),
    test_probabilities
)


# =========================================================
# RESULTS
# =========================================================

print("\n================================")
print("SMS MODEL RESULTS")
print("================================")

print(
    f"Accuracy : {accuracy:.4f}"
)

print(
    f"Precision: {precision:.4f}"
)

print(
    f"Recall   : {recall:.4f}"
)

print(
    f"F1 Score : {f1:.4f}"
)

print(
    f"ROC-AUC  : {roc_auc:.4f}"
)

print("\nConfusion Matrix:")
print(
    f"[[{tn}, {fp}],"
    f"\n [{fn}, {tp}]]"
)


# =========================================================
# SAVE MODEL
# =========================================================

model_data = {

    "model_type":
        "TF-IDF + NumPy Logistic Regression",

    "vocabulary":
        vocabulary,

    "idf":
        idf.tolist(),

    "weights":
        weights.tolist(),

    "bias":
        float(bias),

    "tokenizer":
        "lowercase alphanumeric unigrams + bigrams",

    "classes": {
        "0": "HAM",
        "1": "SPAM"
    }
}


with open(
    MODEL_PATH,
    "w",
    encoding="utf-8",
) as file:

    json.dump(
        model_data,
        file
    )


metadata = {

    "model_type":
        "TF-IDF + NumPy Logistic Regression",

    "dataset":
        "UCI SMS Spam Collection",

    "total_samples":
        len(texts),

    "training_samples":
        len(X_train_text),

    "testing_samples":
        len(X_test_text),

    "vocabulary_size":
        len(vocabulary),

    "test_size":
        0.20,

    "random_state":
        42,

    "metrics": {

        "accuracy":
            float(accuracy),

        "precision":
            float(precision),

        "recall":
            float(recall),

        "f1":
            float(f1),

        "roc_auc":
            float(roc_auc),
    },

    "confusion_matrix": {

        "true_negative":
            tn,

        "false_positive":
            fp,

        "false_negative":
            fn,

        "true_positive":
            tp,
    }
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