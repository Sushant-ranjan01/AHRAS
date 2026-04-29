from datetime import datetime


class EventGenerator:

    def __init__(self):
        pass

    def safe(self, value):
        if value is None:
            return 0
        return value

    def generate_event(self, hybrid_result, risk_result, features):

        event = {
            # 🔥 proper ISO timestamp
            "timestamp": datetime.now().isoformat(),

            # 🔥 safe feature extraction
            "source_ip": features.get("src_ip") or "unknown",
            "packet_count": self.safe(features.get("packet_count")),
            "unique_ports": self.safe(features.get("unique_ports")),
            "protocol": features.get("protocol") or 0,

            # 🔥 hybrid results
            "signature_score": self.safe(hybrid_result.get("signature_score")),
            "anomaly_detected": bool(hybrid_result.get("anomaly_detected")),

            # 🔥 risk results
            "risk_score": self.safe(risk_result.get("risk_score")),
            "threat_level": risk_result.get("threat_level") or "LOW",

            "temporal_attack_density": self.safe(
                risk_result.get("temporal_attack_density")
            ),
            "behavioral_drift": self.safe(
                risk_result.get("behavioral_drift")
            ),

            # 🔥 always list
            "alerts": hybrid_result.get("alerts") or [],

            "response_action": risk_result.get("response_action") or "None"
        }

        return event