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

    def process_packet(self, packet):

        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")

        if not src_ip or not dst_ip:
            return None

        flow_key = (src_ip, dst_ip)

        flow = self.flows[flow_key]

        flow["packet_count"] += 1

        if "dst_port" in packet:
            flow["ports"].add(packet["dst_port"])

        flow["last_seen"] = time.time()

        return {
            "source_ip": src_ip,
            "packet_count": flow["packet_count"],
            "unique_ports": len(flow["ports"]),
            "protocol": packet.get("transport", "OTHER")
        }

    def cleanup_flows(self):
        current_time = time.time()

        expired = [
            key for key, flow in self.flows.items()
            if current_time - flow["last_seen"] > self.timeout
        ]

        for key in expired:
            del self.flows[key]