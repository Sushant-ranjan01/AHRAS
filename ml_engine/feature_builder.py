import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder

DATASET = (
    "ml_engine/datasets/processed/final_dataset.csv"
)

OUTPUT = (
    "ml_engine/datasets/processed/final_features.csv"
)

print("\nLoading processed dataset...\n")

df = pd.read_csv(DATASET)

print("Cleaning column names...")

df.columns = df.columns.str.strip()

print("Encoding labels...")

encoder = LabelEncoder()

df["Label"] = encoder.fit_transform(df["Label"])

print("\nAttack Classes:\n")

for index, label in enumerate(encoder.classes_):

    print(f"{index} --> {label}")

print("\nRemoving non-numeric columns...")

for column in df.columns:

    if df[column].dtype == "object":

        try:
            df[column] = pd.to_numeric(df[column])

        except:
            df.drop(columns=[column], inplace=True)

print("Replacing NaN/Infinite...")

df.replace(
    [np.inf, -np.inf],
    np.nan,
    inplace=True
)

df.dropna(inplace=True)

print("\nFinal Dataset Shape:")

print(df.shape)

print("\nSaving engineered features...")

df.to_csv(
    OUTPUT,
    index=False
)

print("\nFeature Engineering Completed.")