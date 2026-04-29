class SignatureDetector:

    def __init__(self):
        self.port_scan_threshold = 20
        self.packet_rate_threshold = 50
        self.packet_count_threshold = 500

        self.trusted_ports = [80, 443]

    def safe(self, value):
        """Convert safely to number"""
        if value is None:
            return 0
        if isinstance(value, (int, float)):
            return value
        try:
            return int(value)
        except:
            return 0

    def detect(self, features):

        alerts = []
        severity_score = 0

        src_ip = features.get("src_ip")

        # 🔥 SAFE VALUES (CRITICAL FIX)
        unique_ports = self.safe(features.get("unique_ports"))
        packet_rate = self.safe(features.get("packet_rate"))
        packet_count = self.safe(features.get("packet_count"))

        protocol = features.get("protocol")

        # ------------------------------
        # 🚫 Ignore Normal Web Traffic
        # ------------------------------
        if protocol == "TCP" and unique_ports <= 2:
            return {
                "alerts": [],
                "signature_score": 0
            }

        # ------------------------------
        # 🚨 Rule 1: Port Scan Detection
        # ------------------------------
        if unique_ports > self.port_scan_threshold:
            alerts.append({
                "type": "PORT_SCAN",
                "source_ip": src_ip,
                "description": "Multiple ports accessed (possible scanning)"
            })
            severity_score += 40

        # ------------------------------
        # 🚨 Rule 2: Traffic Flood
        # ------------------------------
        if packet_rate > self.packet_rate_threshold and unique_ports > 3:
            alerts.append({
                "type": "TRAFFIC_FLOOD",
                "source_ip": src_ip,
                "description": "High packet rate with multiple ports"
            })
            severity_score += 30

        # ------------------------------
        # 🚨 Rule 3: High Traffic Source
        # ------------------------------
        if packet_count > self.packet_count_threshold and unique_ports > 2:
            alerts.append({
                "type": "HIGH_TRAFFIC_SOURCE",
                "source_ip": src_ip,
                "description": "Unusually high packet volume"
            })
            severity_score += 20

        return {
            "alerts": alerts,
            "signature_score": severity_score
        }