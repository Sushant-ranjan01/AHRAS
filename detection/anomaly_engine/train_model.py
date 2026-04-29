import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os


def train_model():

    print("Training anomaly model...")

    dataset_path = "data/datasets/nsl_kdd/nsl_kdd_sample.csv"

    if not os.path.exists(dataset_path):
        print("❌ Dataset not found:", dataset_path)
        return

    try:
        df = pd.read_csv(dataset_path)
    except Exception as e:
        print("❌ Failed to load dataset:", e)
        return

    required_columns = ["packet_count", "protocol", "src_port", "dst_port"]

    # 🔥 Validate columns
    for col in required_columns:
        if col not in df.columns:
            print(f"❌ Missing column: {col}")
            return

    # 🔥 Clean data
    features = df[required_columns].copy()

    # Convert to numeric safely
    for col in required_columns:
        features[col] = pd.to_numeric(features[col], errors="coerce")

    # Fill NaN with 0
    features = features.fillna(0)

    # Ensure no empty dataset
    if features.empty:
        print("❌ No valid data for training")
        return

    try:
        model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )

        model.fit(features)

        os.makedirs("detection/anomaly_engine", exist_ok=True)

        joblib.dump(model, "detection/anomaly_engine/anomaly_model.pkl")

        print("✔ Model trained and saved")

    except Exception as e:
        print("❌ Training failed:", e)


if __name__ == "__main__":
    train_model()