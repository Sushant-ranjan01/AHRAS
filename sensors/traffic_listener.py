from sensors.flow_generator import FlowGenerator

from detection.hybrid_detection import HybridDetector

from risk_engine.risk_calculator import RiskEngine

from event_management.mongodb_client import MongoDBClient

from event_management.event_schema import EventSchema

from response_engine.alert_system import AlertSystem

from response_engine.rate_limiter import RateLimiter

from ml_engine.predict import predict_attack

from live_logs import add_log


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

        safe_flow = {

            "source_ip":
                flow_data.get("source_ip") or "unknown",

            "destination_ip":
                flow_data.get("destination_ip") or "unknown",

            "packet_count":
                self.safe_num(
                    flow_data.get("packet_count")
                ),

            "protocol":
                self.safe_num(
                    flow_data.get("protocol")
                ),

            "src_port":
                self.safe_num(
                    flow_data.get("src_port")
                ),

            "dst_port":
                self.safe_num(
                    flow_data.get("dst_port")
                ),

            "unique_ports":
                self.safe_num(
                    flow_data.get("unique_ports")
                ),

            "flow_duration":
                self.safe_num(
                    flow_data.get("flow_duration")
                ),

            "flow_packets_per_second":
                self.safe_num(
                    flow_data.get(
                        "flow_packets_per_second"
                    )
                ),

            "total_bytes":
                self.safe_num(
                    flow_data.get("total_bytes")
                ),

            "avg_packet_size":
                self.safe_num(
                    flow_data.get(
                        "avg_packet_size"
                    )
                ),

            "syn_count":
                self.safe_num(
                    flow_data.get("syn_count")
                ),

            "ack_count":
                self.safe_num(
                    flow_data.get("ack_count")
                ),

            "rst_count":
                self.safe_num(
                    flow_data.get("rst_count")
                ),

            "fin_count":
                self.safe_num(
                    flow_data.get("fin_count")
                ),

            "forward_packets":
                self.safe_num(
                    flow_data.get(
                        "forward_packets"
                    )
                )
        }

        src_ip = safe_flow["source_ip"]

        # RATE LIMIT

        if self.rate_limiter.is_rate_limited(src_ip):

            print(
                f"[RATE LIMIT] High traffic from {src_ip}"
            )

        # AI PREDICTION

        ml_result = predict_attack(safe_flow)

        safe_flow["ml_prediction"] = (
            ml_result.get("attack_type")
        )

        # RULE/HYBRID DETECTION

        hybrid_result = self.detector.detect(
            safe_flow
        )

        hybrid_result["ml_prediction"] = (
            ml_result.get("attack_type")
        )

        # RISK ENGINE

        risk_result = self.risk_engine.calculate_risk(

            hybrid_result,

            {
                "src_ip": src_ip,

                "packet_count":
                    safe_flow.get(
                        "packet_count",
                        0
                    )
            }
        )

        # FINAL EVENT

        final_event = EventSchema.create(

            safe_flow,

            hybrid_result,

            risk_result
        )

        # LOGGING

        attack_types = final_event.get(
            "matched_rules",
            []
        )

        if attack_types:

            attack_label = ", ".join(
                attack_types
            )

        else:

            attack_label = "Normal"

        protocol = final_event.get(
            "protocol",
            0
        )

        if protocol == 6:

            proto_name = "TCP"

        elif protocol == 17:

            proto_name = "UDP"

        elif protocol == 1:

            proto_name = "ICMP"

        else:

            proto_name = "OTHER"

        log_message = (

            f"[{final_event.get('threat_level')}] "

            f"{final_event.get('source_ip')} "

            f"| {proto_name} "

            f"| Risk={final_event.get('risk_score')} "

            f"| ML={ml_result.get('attack_type')} "

            f"| {attack_label}"
        )

        print(log_message)

        add_log(log_message)

        # DATABASE STORAGE

        try:

            self.db.insert_event(final_event)

            print("Stored in MongoDB")

        except Exception as e:

            print("DB Error:", e)

        # ALERTS

        if (

            risk_result.get(
                "threat_level"
            )

            in ["HIGH", "CRITICAL"]
        ):

            self.alert_system.generate_alert(
                risk_result
            )

        # CLEANUP

        self.flow_generator.cleanup_flows()