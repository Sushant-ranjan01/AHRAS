import pandas as pd

from sklearn.model_selection import train_test_split

from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    classification_report,
    accuracy_score,
    confusion_matrix
)

import joblib


DATASET = (
    "ml_engine/datasets/processed/runtime_features.csv"
)

MODEL_OUTPUT = (
    "ml_engine/models/runtime_random_forest.pkl"
)

print("\nLoading runtime dataset...\n")

df = pd.read_csv(DATASET)

print("Preparing features and labels...\n")

X = df.drop(columns=["Label"])

y = df["Label"]

print("Splitting dataset...\n")

X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.2,

    random_state=42
)

print("Training Runtime-Compatible Model...\n")

model = RandomForestClassifier(

    n_estimators=100,

    random_state=42,

    n_jobs=-1
)

model.fit(X_train, y_train)

print("\nModel Training Completed.")

print("\nRunning Predictions...\n")

predictions = model.predict(X_test)

accuracy = accuracy_score(
    y_test,
    predictions
)

print(f"\nAccuracy: {accuracy * 100:.2f}%")

print("\nClassification Report:\n")

print(
    classification_report(
        y_test,
        predictions
    )
)

print("\nConfusion Matrix:\n")

print(
    confusion_matrix(
        y_test,
        predictions
    )
)

print("\nSaving runtime model...\n")

joblib.dump(
    model,
    MODEL_OUTPUT
)

print(
    f"\nRuntime model saved at:\n{MODEL_OUTPUT}"
)