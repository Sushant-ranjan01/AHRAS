from feature_engineering.flow_features import FlowFeatures
from feature_engineering.preprocessing import Preprocessor


class FeatureExtractor:

    def __init__(self):
        self.flow_features = FlowFeatures()
        self.preprocessor = Preprocessor()

    def safe(self, value):
        if value is None:
            return 0
        if isinstance(value, (int, float)):
            return value
        try:
            return int(value)
        except:
            return 0

    def extract(self, flow_data):

        try:
            raw = self.flow_features.extract(flow_data) or {}
        except Exception as e:
            print("Flow feature error:", e)
            raw = {}

        safe_features = {
            "packet_count": self.safe(raw.get("packet_count")),
            "protocol": self.safe(raw.get("protocol")),
            "src_port": self.safe(raw.get("src_port")),
            "dst_port": self.safe(raw.get("dst_port"))
        }

        try:
            processed = self.preprocessor.normalize(safe_features)

            if not isinstance(processed, dict):
                processed = safe_features

        except Exception as e:
            print("Preprocessing error:", e)
            processed = safe_features

        for k in safe_features:
            if k not in processed:
                processed[k] = safe_features[k]

        return processed