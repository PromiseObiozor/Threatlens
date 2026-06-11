import os
import joblib
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
    ConfusionMatrixDisplay,
)

DATASET_PATH = "ml/data/enron_spam_data.csv"
MODEL_OUTPUT_PATH = "ml/models/threatlens_baseline_model.joblib"
CONFUSION_MATRIX_PATH = "ml/models/baseline_confusion_matrix.png"


def load_dataset():
    df = pd.read_csv(DATASET_PATH)

    # Keep only the useful columns
    df = df[["Subject", "Message", "Spam/Ham"]]

    # Remove rows where subject or message is missing
    df = df.dropna(subset=["Subject", "Message", "Spam/Ham"])

    # Combine subject and body into one text field
    df["text"] = df["Subject"].astype(str) + " " + df["Message"].astype(str)

    # Convert labels into numbers
    # ham = 0, spam = 1
    df["label"] = df["Spam/Ham"].map({
        "ham": 0,
        "spam": 1
    })

    # Remove rows if label mapping failed
    df = df.dropna(subset=["label"])

    df["label"] = df["label"].astype(int)

    return df


def train_model(df):
    X = df["text"]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                stop_words="english",
                max_features=10000,
                ngram_range=(1, 2)
            )
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced"
            )
        )
    ])

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    probabilities = model.predict_proba(X_test)[:, 1]

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions)
    recall = recall_score(y_test, predictions)
    f1 = f1_score(y_test, predictions)

    print("\nMODEL PERFORMANCE")
    print("-----------------")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")

    print("\nCLASSIFICATION REPORT")
    print("---------------------")
    print(classification_report(y_test, predictions, target_names=["ham", "spam"]))

    cm = confusion_matrix(y_test, predictions)

    display = ConfusionMatrixDisplay(
        confusion_matrix=cm,
        display_labels=["ham", "spam"]
    )

    display.plot()
    plt.title("ThreatLens Baseline Model - Confusion Matrix")
    plt.savefig(CONFUSION_MATRIX_PATH)
    plt.close()

    print(f"\nConfusion matrix saved to: {CONFUSION_MATRIX_PATH}")

    return model


def save_model(model):
    os.makedirs("ml/models", exist_ok=True)
    joblib.dump(model, MODEL_OUTPUT_PATH)
    print(f"Model saved to: {MODEL_OUTPUT_PATH}")


if __name__ == "__main__":
    print("Loading dataset...")
    dataset = load_dataset()

    print(f"Dataset ready. Rows after cleaning: {len(dataset)}")
    print("\nLabel counts after cleaning:")
    print(dataset["label"].value_counts())

    print("\nTraining baseline model...")
    trained_model = train_model(dataset)

    print("\nSaving model...")
    save_model(trained_model)

    print("\nDone.")