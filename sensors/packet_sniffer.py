"""
Captures live packets from a network interface and publishes
raw flow records to Kafka topic: raw.telemetry
"""

import json
import time
import uuid
import logging
from collections import defaultdict
from datetime import datetime, timezone

from scapy.all import sniff, IP, TCP, UDP, ICMP
from kafka import KafkaProducer

from config.settings import (
    KAFKA_BOOTSTRAP, KAFKA_TOPIC_RAW,
    NETWORK_INTERFACE, FLOW_WINDOW_SECONDS
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SNIFFER] %(message)s")
log = logging.getLogger(__name__)

# In-memory flow aggregation table
# key: (src_ip, dst_ip, src_port, dst_port, protocol)
_flows: dict = defaultdict(lambda: {
    "packet_count": 0,
    "byte_count": 0,
    "start_time": None,
    "flags": set(),
    "unique_dst_ports": set(),
})


def _make_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=5,
    )


def _build_raw_event(flow_key: tuple, flow: dict) -> dict:
    src_ip, dst_ip, src_port, dst_port, proto = flow_key
    return {
        "event_id": str(uuid.uuid4()),
        "source": "network_tap",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "packet_count": flow["packet_count"],
        "byte_count": flow["byte_count"],
        "duration_sec": time.time() - flow["start_time"] if flow["start_time"] else 0,
        "tcp_flags": list(flow["flags"]),
        "unique_dst_ports": len(flow["unique_dst_ports"]),
    }


def _packet_callback(pkt, producer: KafkaProducer):
    if not pkt.haslayer(IP):
        return

    ip = pkt[IP]
    src_ip, dst_ip = ip.src, ip.dst
    proto, src_port, dst_port, flags = "OTHER", 0, 0, set()

    if pkt.haslayer(TCP):
        proto = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        f = pkt[TCP].flags
        if f & 0x02: flags.add("SYN")
        if f & 0x10: flags.add("ACK")
        if f & 0x01: flags.add("FIN")
        if f & 0x04: flags.add("RST")
    elif pkt.haslayer(UDP):
        proto = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        proto = "ICMP"

    key = (src_ip, dst_ip, src_port, dst_port, proto)
    flow = _flows[key]

    if flow["start_time"] is None:
        flow["start_time"] = time.time()

    flow["packet_count"] += 1
    flow["byte_count"] += len(pkt)
    flow["flags"].update(flags)
    flow["unique_dst_ports"].add(dst_port)

    # Flush flows older than FLOW_WINDOW_SECONDS
    now = time.time()
    to_flush = [k for k, v in _flows.items()
                if v["start_time"] and now - v["start_time"] >= FLOW_WINDOW_SECONDS]

    for fk in to_flush:
        event = _build_raw_event(fk, _flows.pop(fk))
        producer.send(KAFKA_TOPIC_RAW, value=event)
        log.info(f"Flow published: {fk[0]} → {fk[1]} [{fk[4]}] pkts={event['packet_count']}")


def start_sniffer():
    producer = _make_producer()
    log.info(f"Sniffing on interface: {NETWORK_INTERFACE}")
    sniff(
        iface=NETWORK_INTERFACE,
        prn=lambda pkt: _packet_callback(pkt, producer),
        store=False,
    )


if __name__ == "__main__":
    start_sniffer()