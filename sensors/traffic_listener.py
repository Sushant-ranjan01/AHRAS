from sensors.flow_generator import FlowGenerator
from detection.hybrid_detection import HybridDetector
from risk_engine.risk_calculator import RiskEngine

from event_management.mongodb_client import MongoDBClient
from event_management.event_schema import EventSchema

from response_engine.alert_system import AlertSystem
from response_engine.rate_limiter import RateLimiter


class TrafficListener:

    def __init__(self):

        self.flow_generator = FlowGenerator()
        self.detector = HybridDetector()
        self.risk_engine = RiskEngine()

        self.db = MongoDBClient()

        self.alert_system = AlertSystem()
        self.rate_limiter = RateLimiter()

    def safe_num(self, value):
        if value is None:
            return 0
        if isinstance(value, (int, float)):
            return value
        try:
            return int(value)
        except:
            return 0

    def handle_packet(self, packet):

        flow_data = self.flow_generator.process_packet(packet)

        if not flow_data:
            return

        # 🔥 SAFE FLOW (DO NOT TOUCH IPs)
        safe_flow = {
            "source_ip": flow_data.get("source_ip") or "unknown",
            "destination_ip": flow_data.get("destination_ip") or "unknown",

            "packet_count": self.safe_num(flow_data.get("packet_count")),
            "protocol": self.safe_num(flow_data.get("protocol")),
            "src_port": self.safe_num(flow_data.get("src_port")),
            "dst_port": self.safe_num(flow_data.get("dst_port")),
            "unique_ports": self.safe_num(flow_data.get("unique_ports")),
        }

        src_ip = safe_flow["source_ip"]

        # 🔥 Rate limit check
        if self.rate_limiter.is_rate_limited(src_ip):
            print(f"[RATE LIMIT] High traffic from {src_ip}")

        # Detection
        hybrid_result = self.detector.detect(safe_flow)

        # Risk
        risk_result = self.risk_engine.calculate_risk(
            hybrid_result,
            {
                "src_ip": src_ip,
                "packet_count": safe_flow.get("packet_count", 0)
            }
        )

        final_event = EventSchema.create(
            safe_flow,
            hybrid_result,
            risk_result
        )

        print("\n=== SECURITY EVENT ===")
        print(final_event)

        try:
            self.db.insert_event(final_event)
            print("✔ Stored in MongoDB")
        except Exception as e:
            print("❌ DB Error:", e)

        if (risk_result.get("threat_level") or "") in ["HIGH", "CRITICAL"]:
            self.alert_system.generate_alert(risk_result)

        self.flow_generator.cleanup_flows()