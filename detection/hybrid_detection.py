from detection.signature_engine.signature_detector import SignatureDetector
from detection.anomaly_engine.predict_anomaly import AnomalyDetector
from feature_engineering.feature_extractor import FeatureExtractor


class HybridDetector:

    def __init__(self):
        self.signature_detector = SignatureDetector()
        self.anomaly_detector = AnomalyDetector()
        self.feature_extractor = FeatureExtractor()

    def detect(self, flow_data):

        # 🔥 DO NOT destroy flow_data
        safe_flow = flow_data

        # 🔥 Ensure required fields exist
        safe_flow.setdefault("unique_ports", 0)
        safe_flow.setdefault("packet_count", 0)
        safe_flow.setdefault("protocol", 0)

        # 🔹 Signature detection (USES FLOW DATA)
        signature_result = self.signature_detector.detect(safe_flow)

        # 🔹 Feature extraction (FOR ML ONLY)
        features = self.feature_extractor.extract(safe_flow)

        if not isinstance(features, dict):
            features = {}

        # 🔹 ML anomaly detection
        anomaly_flag = self.anomaly_detector.predict(features)

        return {
    "signature_score": signature_result.get("signature_score", 0),

    "alerts": signature_result.get("alerts", []),

    "matched_rules": [
        alert.get("type")
        for alert in signature_result.get("alerts", [])
    ],

    "anomaly_detected": anomaly_flag
}