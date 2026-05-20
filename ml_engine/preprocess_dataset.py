import pandas as pd
import os

RAW_FOLDER = "ml_engine/datasets/raw"

OUTPUT_FILE = (
    "ml_engine/datasets/processed/final_dataset.csv"
)

all_dataframes = []

print("\nLoading parquet datasets...\n")

for file in os.listdir(RAW_FOLDER):

    if file.endswith(".parquet"):

        path = os.path.join(RAW_FOLDER, file)

        print(f"Reading: {file}")

        try:

            df = pd.read_parquet(path)

            all_dataframes.append(df)

        except Exception as e:

            print(f"Error reading {file}: {e}")

print("\nMerging datasets...\n")

combined_df = pd.concat(
    all_dataframes,
    ignore_index=True
)

print("Cleaning dataset...")

combined_df.replace(
    [float("inf"), -float("inf")],
    pd.NA,
    inplace=True
)

combined_df.dropna(inplace=True)

combined_df.columns = (
    combined_df.columns.str.strip()
)

print("\nDataset Shape:")
print(combined_df.shape)

print("\nAttack Labels:\n")

print(
    combined_df["Label"].value_counts()
)

print("\nSaving processed dataset...")

combined_df.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\nPreprocessing Completed.")