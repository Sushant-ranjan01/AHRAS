from datetime import datetime


class EventSchema:

    @staticmethod
    def create(flow_data, hybrid_result, risk_result):

        return {

            "timestamp": str(datetime.now()),

            "source_ip": flow_data.get("source_ip"),
            "destination_ip": flow_data.get("destination_ip"),
            "protocol": flow_data.get("protocol"),
            "src_port": flow_data.get("src_port"),
            "dst_port": flow_data.get("dst_port"),

            "packet_count": flow_data.get("packet_count"),

            "signature_score": hybrid_result.get("signature_score", 0),
            "matched_rules": hybrid_result.get("matched_rules", []),
            "anomaly_detected": hybrid_result.get("anomaly_detected", False),

            "risk_score": risk_result.get("risk_score", 0),
            "threat_level": risk_result.get("threat_level", "LOW"),
            "packet_rate": risk_result.get("packet_rate", 0),
            "behavioral_drift": risk_result.get("behavioral_drift", 0),
            "trust_score": risk_result.get("trust_score", 0),

            "response_action": risk_result.get("response_action", "Monitored")
        }