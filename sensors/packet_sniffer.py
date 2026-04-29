from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
from sensors.traffic_listener import TrafficListener
import traceback

listener = TrafficListener()


def safe_int(value):
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(value)
    except:
        return 0


def process_packet(packet):
    try:
        if not packet.haslayer(IP):
            return None

        ip_layer = packet.getlayer(IP)

        src_ip = ip_layer.src or "unknown"
        dst_ip = ip_layer.dst or "unknown"

        protocol = safe_int(ip_layer.proto)

        src_port = 0
        dst_port = 0

        if packet.haslayer(TCP):
            tcp = packet.getlayer(TCP)
            src_port = safe_int(tcp.sport)
            dst_port = safe_int(tcp.dport)

        elif packet.haslayer(UDP):
            udp = packet.getlayer(UDP)
            src_port = safe_int(udp.sport)
            dst_port = safe_int(udp.dport)

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_length": safe_int(len(packet)),
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        print("Packet processing error:", e)
        traceback.print_exc()
        return None


def safe_handler(packet):
    try:
        parsed = process_packet(packet)

        if parsed:
            listener.handle_packet(parsed)

    except Exception:
        print("\n🔥🔥🔥 FULL TRACEBACK (REAL ERROR) 🔥🔥🔥")
        traceback.print_exc()


def start_sniffing():

    print("AHRAS Packet Sniffer Started...\n")

    sniff(
        prn=safe_handler,
        store=False
    )


if __name__ == "__main__":
    start_sniffing()