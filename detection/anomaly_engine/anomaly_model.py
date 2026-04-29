from sklearn.ensemble import IsolationForest
import numpy as np


class AnomalyDetector:

    def __init__(self):
        self.model = IsolationForest(
            contamination=0.05,
            random_state=42
        )
        self.trained = False

    def safe_vector(self, vector):
        """Ensure all values are numeric"""
        clean = []

        for v in vector:
            if isinstance(v, (int, float)):
                clean.append(v)
            else:
                try:
                    clean.append(float(v))
                except:
                    clean.append(0)

        return clean

    def train(self, training_data):

        try:
            X = np.array(training_data)

            if len(X.shape) != 2:
                print("Invalid training data shape")
                return

            self.model.fit(X)
            self.trained = True

            print("Anomaly model trained successfully.")

        except Exception as e:
            print("Training error:", e)

    def predict(self, feature_vector):

        if not self.trained:
            return {"anomaly_score": 0, "is_anomaly": False}

        try:
            # 🔥 sanitize input
            feature_vector = self.safe_vector(feature_vector)

            X = np.array([feature_vector])

            if len(X.shape) != 2:
                return {"anomaly_score": 0, "is_anomaly": False}

            prediction = self.model.predict(X)
            score = self.model.decision_function(X)

            return {
                "anomaly_score": float(score[0]),
                "is_anomaly": True if prediction[0] == -1 else False
            }

        except Exception as e:
            print("Prediction error:", e)
            return {"anomaly_score": 0, "is_anomaly": False}