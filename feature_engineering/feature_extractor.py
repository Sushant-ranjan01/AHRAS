from collections import defaultdict
import time


class FeatureExtractor:

    def __init__(self):
        self.ip_packet_count = defaultdict(int)
        self.ip_ports = defaultdict(set)
        self.protocol_count = defaultdict(int)
        self.packet_timestamps = []

    def extract_features(self, packet_data):

        src_ip = packet_data.get("src_ip")
        dst_port = packet_data.get("dst_port")
        protocol = packet_data.get("transport")

        # Count packets per source IP
        self.ip_packet_count[src_ip] += 1

        # Track accessed ports
        if dst_port:
            self.ip_ports[src_ip].add(dst_port)

        # Track protocol usage
        if protocol:
            self.protocol_count[protocol] += 1

        # Track timestamps
        self.packet_timestamps.append(time.time())

        # Calculate packet rate
        packet_rate = self.calculate_packet_rate()

        features = {
            "src_ip": src_ip,
            "packet_count": self.ip_packet_count[src_ip],
            "unique_ports": len(self.ip_ports[src_ip]),
            "protocol": protocol,
            "packet_rate": packet_rate
        }

        return features

    def calculate_packet_rate(self):

        current_time = time.time()

        # Keep only last 10 seconds
        self.packet_timestamps = [
            t for t in self.packet_timestamps
            if current_time - t <= 10
        ]

        return len(self.packet_timestamps) / 10