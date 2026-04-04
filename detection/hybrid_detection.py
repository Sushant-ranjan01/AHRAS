class HybridDetector:

    def __init__(self):
        # weights for hybrid model (static baseline)
        self.signature_weight = 0.6
        self.anomaly_weight = 0.4

    def evaluate(self, signature_result, anomaly_result):

        signature_score = signature_result.get("signature_score", 0)
        anomaly_flag = anomaly_result.get("is_anomaly", False)

        anomaly_score = 50 if anomaly_flag else 0

        hybrid_score = (
            self.signature_weight * signature_score +
            self.anomaly_weight * anomaly_score
        )

        threat_level = self.calculate_threat_level(hybrid_score)

        result = {
            "signature_score": signature_score,
            "anomaly_detected": anomaly_flag,
            "hybrid_score": hybrid_score,
            "threat_level": threat_level,
            "alerts": signature_result.get("alerts", [])
        }

        return result

    def calculate_threat_level(self, score):

        if score >= 70:
            return "CRITICAL"

        elif score >= 40:
            return "HIGH"

        elif score >= 20:
            return "MEDIUM"

        else:
            return "LOW"