from sklearn.ensemble import IsolationForest
import numpy as np


class AnomalyDetector:

    def __init__(self):
        self.model = IsolationForest(
            contamination=0.05,
            random_state=42
        )
        self.trained = False

    def train(self, training_data):

        """
        Train the anomaly model using normal network traffic
        """

        X = np.array(training_data)

        self.model.fit(X)
        self.trained = True

        print("Anomaly model trained successfully.")

    def predict(self, feature_vector):

        """
        Predict whether behavior is normal or anomalous
        """

        if not self.trained:
            print("Model not trained yet.")
            return {"anomaly_score": 0, "is_anomaly": False}

        X = np.array([feature_vector])

        prediction = self.model.predict(X)
        score = self.model.decision_function(X)

        result = {
            "anomaly_score": float(score[0]),
            "is_anomaly": True if prediction[0] == -1 else False
        }

        return result