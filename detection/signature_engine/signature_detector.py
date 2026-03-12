class SignatureDetector:

    def __init__(self):
        # thresholds can later be moved to config file
        self.port_scan_threshold = 10
        self.packet_rate_threshold = 20
        self.packet_count_threshold = 100

    def detect(self, features):

        alerts = []
        severity_score = 0

        src_ip = features.get("src_ip")
        unique_ports = features.get("unique_ports")
        packet_rate = features.get("packet_rate")
        packet_count = features.get("packet_count")

        # Rule 1: Port Scan Detection
        if unique_ports > self.port_scan_threshold:
            alerts.append({
                "type": "PORT_SCAN",
                "source_ip": src_ip,
                "description": "Multiple ports accessed by same IP"
            })
            severity_score += 40

        # Rule 2: Packet Flood / Possible DoS
        if packet_rate > self.packet_rate_threshold:
            alerts.append({
                "type": "TRAFFIC_FLOOD",
                "source_ip": src_ip,
                "description": "High packet rate detected"
            })
            severity_score += 30

        # Rule 3: Suspicious Packet Volume
        if packet_count > self.packet_count_threshold:
            alerts.append({
                "type": "HIGH_TRAFFIC_SOURCE",
                "source_ip": src_ip,
                "description": "Unusually high packet count from source"
            })
            severity_score += 20

        result = {
            "alerts": alerts,
            "signature_score": severity_score
        }

        return result