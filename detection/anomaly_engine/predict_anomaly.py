import joblib
import pandas as pd


class AnomalyDetector:

    def __init__(self):
        self.model = joblib.load("detection/anomaly_engine/anomaly_model.pkl")

        # 🔥 MUST MATCH TRAINING FEATURES EXACTLY
        self.feature_names = ["packet_count", "protocol", "src_port", "dst_port"]

    def safe(self, value):
        if value is None:
            return 0
        if isinstance(value, (int, float)):
            return value
        try:
            return int(value)
        except:
            return 0

    def predict(self, features):

        try:
            # 🔥 CLEAN + STRUCTURED INPUT
            data = {
                "packet_count": self.safe(features.get("packet_count")),
                "protocol": self.safe(features.get("protocol")),
                "src_port": self.safe(features.get("src_port")),
                "dst_port": self.safe(features.get("dst_port"))
            }

            # 🔥 CONVERT TO DATAFRAME (CRITICAL FIX)
            df = pd.DataFrame([data], columns=self.feature_names)

            prediction = self.model.predict(df)

            # -1 = anomaly
            return prediction[0] == -1

        except Exception as e:
            print("Anomaly prediction error:", e)
            return False