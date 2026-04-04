from datetime import datetime


class EventGenerator:

    def __init__(self):
        pass

    def generate_event(self, hybrid_result, risk_result, features):

        event = {
            "timestamp": str(datetime.now()),
            "source_ip": features.get("src_ip"),
            "packet_count": features.get("packet_count"),
            "unique_ports": features.get("unique_ports"),
            "protocol": features.get("protocol"),

            "signature_score": hybrid_result.get("signature_score"),
            "anomaly_detected": hybrid_result.get("anomaly_detected"),

            "risk_score": risk_result.get("risk_score"),
            "threat_level": risk_result.get("threat_level"),

            "temporal_attack_density": risk_result.get("temporal_attack_density"),
            "behavioral_drift": risk_result.get("behavioral_drift"),

            "alerts": hybrid_result.get("alerts"),

            "response_action": None
        }

        return event