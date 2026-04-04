from sensors.packet_sniffer import process_packet
from feature_engineering.feature_extractor import FeatureExtractor
from detection.signature_engine.signature_detector import SignatureDetector
from detection.anomaly_engine.anomaly_model import AnomalyDetector
from detection.hybrid_detection import HybridDetector
from risk_engine.risk_calculator import RiskEngine
from event_management.event_generator import EventGenerator
from event_management.mongodb_client import MongoDBClient
from response_engine.ip_blocker import IPBlocker

from scapy.all import sniff
import socket


# Auto-detect local IP
LOCAL_IP = socket.gethostbyname(socket.gethostname())


# Initialize modules
feature_extractor = FeatureExtractor()
signature_detector = SignatureDetector()
anomaly_detector = AnomalyDetector()
hybrid_detector = HybridDetector()
risk_engine = RiskEngine()
event_generator = EventGenerator()
mongo_client = MongoDBClient()
ip_blocker = IPBlocker()


# ---- TEMPORARY TRAINING ----
training_data = [
    [10, 2, 1],
    [15, 3, 1.2],
    [20, 4, 1.5],
    [25, 5, 2],
    [30, 6, 2.5]
]

anomaly_detector.train(training_data)


# ---- MAIN PIPELINE ----
def process_pipeline(packet):

    # Step 1: parse packet
    packet_data = process_packet(packet)

    if not packet_data:
        return

    # Ignore local machine traffic
    if packet_data.get("src_ip") == LOCAL_IP:
        return

    # Step 2: feature extraction
    features = feature_extractor.extract_features(packet_data)

    # Step 3: signature detection
    signature_result = signature_detector.detect(features)

    # Step 4: anomaly detection
    feature_vector = [
        features["packet_count"],
        features["unique_ports"],
        features["packet_rate"]
    ]

    anomaly_result = anomaly_detector.predict(feature_vector)

    # Step 5: hybrid detection
    hybrid_result = hybrid_detector.evaluate(signature_result, anomaly_result)

    # Step 6: risk calculation
    risk_result = risk_engine.calculate_risk(hybrid_result, features)

    # Ignore low-risk noise
    if risk_result["risk_score"] < 20:
        return

    # Step 7: automatic response
    if risk_result["threat_level"] in ["HIGH", "CRITICAL"]:
        action = ip_blocker.block_ip(risk_result["source_ip"])
    else:
        action = None

    # Step 8: generate event
    event = event_generator.generate_event(
        hybrid_result,
        risk_result,
        features
    )

    event["response_action"] = action

    # Add blocker status
    status = ip_blocker.get_status()
    event["total_blocked_ips"] = status["total_blocked"]
    event["recent_blocked_ips"] = status["recent_blocks"]

    # Step 9: store in MongoDB
    mongo_client.insert_event(event)

    # Step 10: print alerts
    if event["threat_level"] in ["HIGH", "CRITICAL"]:
        print("\n=== SECURITY ALERT ===")
        print("Blocked:", event["response_action"])
        print("Total Blocked IPs:", event["total_blocked_ips"])
        print("Recent Blocked IPs:", event["recent_blocked_ips"])
        print("Full Event:", event)


# ---- START SYSTEM ----
def start_ahras():

    print("\nAHRAS Security Platform Started...\n")
    print("No IPs blocked yet.\n")

    sniff(
        prn=process_pipeline,
        store=False
    )


if __name__ == "__main__":
    start_ahras()