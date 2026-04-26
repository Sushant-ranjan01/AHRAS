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

        # 🔥 Connected components
        self.alert_system = AlertSystem()
        self.rate_limiter = RateLimiter()

    def handle_packet(self, packet):

        # STEP 1 → Flow generation
        flow_data = self.flow_generator.process_packet(packet)

        if not flow_data:
            return

        src_ip = flow_data.get("source_ip")

        # STEP 2 → Rate limiting (monitor only)
        if self.rate_limiter.is_rate_limited(src_ip):
            print(f"[RATE LIMIT] High traffic from {src_ip}")

        # STEP 3 → Detection
        hybrid_result = self.detector.detect(flow_data)

        # STEP 4 → Risk calculation
        risk_result = self.risk_engine.calculate_risk(
            hybrid_result,
            {
                "src_ip": src_ip,
                "packet_count": flow_data.get("packet_count", 0)
            }
        )

        # STEP 5 → Structured event
        final_event = EventSchema.create(
            flow_data,
            hybrid_result,
            risk_result
        )

        # STEP 6 → Print (debug)
        print("\n=== SECURITY EVENT ===")
        print(final_event)

        # STEP 7 → Store in DB
        try:
            self.db.insert_event(final_event)
            print("✔ Stored in MongoDB")
        except Exception as e:
            print("❌ DB Error:", e)

        # STEP 8 → Alerting (ONLY HIGH / CRITICAL)
        if risk_result.get("threat_level") in ["HIGH", "CRITICAL"]:
            self.alert_system.generate_alert(risk_result)

        # STEP 9 → Cleanup
        self.flow_generator.cleanup_flows()