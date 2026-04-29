from datetime import datetime


class EventSchema:

    @staticmethod
    def safe(value, default=0):
        if value is None:
            return default
        return value

    @staticmethod
    def create(flow_data, hybrid_result, risk_result):

        return {

            # 🔥 standardized timestamp
            "timestamp": datetime.now().isoformat(),

            # 🔥 flow data (safe)
            "source_ip": flow_data.get("source_ip") or "unknown",
            "destination_ip": flow_data.get("destination_ip") or "unknown",
            "protocol": flow_data.get("protocol") or 0,
            "src_port": EventSchema.safe(flow_data.get("src_port")),
            "dst_port": EventSchema.safe(flow_data.get("dst_port")),

            "packet_count": EventSchema.safe(flow_data.get("packet_count")),

            # 🔥 hybrid
            "signature_score": EventSchema.safe(
                hybrid_result.get("signature_score"), 0
            ),
            "matched_rules": hybrid_result.get("matched_rules") or [],
            "anomaly_detected": bool(
                hybrid_result.get("anomaly_detected")
            ),

            # 🔥 risk
            "risk_score": EventSchema.safe(
                risk_result.get("risk_score"), 0
            ),
            "threat_level": risk_result.get("threat_level") or "LOW",
            "packet_rate": EventSchema.safe(
                risk_result.get("packet_rate"), 0
            ),
            "behavioral_drift": EventSchema.safe(
                risk_result.get("behavioral_drift"), 0
            ),
            "trust_score": EventSchema.safe(
                risk_result.get("trust_score"), 0
            ),

            "response_action": risk_result.get("response_action") or "Monitored"
        }