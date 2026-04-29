from collections import defaultdict
import time


class FlowGenerator:

    def __init__(self):
        self.flows = defaultdict(lambda: {
            "packet_count": 0,
            "ports": set(),
            "last_seen": time.time()
        })
        self.timeout = 10

    def safe_int(self, value):
        if value is None:
            return 0
        if isinstance(value, (int, float)):
            return int(value)
        try:
            return int(value)
        except:
            return 0

    def process_packet(self, packet):
        try:
            # 🔥 validate packet
            if not isinstance(packet, dict):
                return None

            src_ip = packet.get("src_ip") or "unknown"
            dst_ip = packet.get("dst_ip") or "unknown"

            flow_key = (src_ip, dst_ip)

            flow = self.flows[flow_key]
            flow["packet_count"] += 1

            src_port = self.safe_int(packet.get("src_port"))
            dst_port = self.safe_int(packet.get("dst_port"))

            if dst_port:
                flow["ports"].add(dst_port)

            flow["last_seen"] = time.time()

            return {
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "packet_count": int(flow["packet_count"]),
                "protocol": self.safe_int(packet.get("protocol")),
                "src_port": src_port,
                "dst_port": dst_port,
                "unique_ports": len(flow["ports"])
            }

        except Exception as e:
            print("Flow error:", e)
            return None

    def cleanup_flows(self):
        current_time = time.time()

        expired = [
            key for key, flow in self.flows.items()
            if current_time - flow["last_seen"] > self.timeout
        ]

        for key in expired:
            del self.flows[key]