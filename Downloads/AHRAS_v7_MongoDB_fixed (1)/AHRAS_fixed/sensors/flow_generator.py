"""
AHRAS — Flow Generator (Phase 2)
Aggregates raw packets into FlowRecord objects and emits them periodically.
"""
import time, queue, threading, logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from sensors.packet_sniffer import RawPacket

logger = logging.getLogger("ahras.flow")
FLOW_TIMEOUT = 5.0
FLOW_MAX_PKTS = 500

@dataclass
class FlowRecord:
    flow_id: str
    src_ip: str; dst_ip: str; protocol: str
    src_port: int; dst_port: int
    packet_count: int = 0
    byte_count: int = 0
    unique_ports: int = 0
    unique_dst_ports: set = field(default_factory=set)
    tcp_flags: List[str] = field(default_factory=list)
    avg_packet_size: float = 0.0
    max_packet_size: int = 0
    min_packet_size: int = 9999
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    duration: float = 0.0
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0

    def finalise(self):
        self.duration = max(self.last_seen - self.start_time, 0.001)
        self.unique_ports = len(self.unique_dst_ports)
        self.avg_packet_size = self.byte_count / max(self.packet_count, 1)
        self.packets_per_second = self.packet_count / self.duration
        self.bytes_per_second   = self.byte_count   / self.duration

class FlowGenerator:
    def __init__(self, pkt_q: queue.Queue, flow_q: queue.Queue):
        self.pkt_q = pkt_q; self.flow_q = flow_q
        self._stop = threading.Event()
        self._flows: Dict[Tuple, FlowRecord] = {}
        self._lock = threading.Lock()
        self.emitted = 0

    def start(self):
        threading.Thread(target=self._consume, daemon=True).start()
        threading.Thread(target=self._reaper,  daemon=True).start()
        logger.info("FlowGenerator started")

    def stop(self):
        self._stop.set()

    def _key(self, p: RawPacket): return (p.src_ip, p.dst_ip, p.protocol)

    def _consume(self):
        from sensors.packet_sniffer import _LOCAL_IPS
        while not self._stop.is_set():
            try: pkt = self.pkt_q.get(timeout=1.0)
            except queue.Empty: continue
            # Skip any packet sourced from this machine — own traffic is noise
            if pkt.src_ip in _LOCAL_IPS:
                continue
            key = self._key(pkt); now = time.time()
            with self._lock:
                if key not in self._flows:
                    self._flows[key] = FlowRecord(
                        flow_id=f"{pkt.src_ip}-{pkt.protocol}-{int(now)}",
                        src_ip=pkt.src_ip, dst_ip=pkt.dst_ip,
                        protocol=pkt.protocol, src_port=pkt.src_port,
                        dst_port=pkt.dst_port, start_time=now, last_seen=now)
                f = self._flows[key]
                f.packet_count += 1; f.byte_count += pkt.length; f.last_seen = now
                f.unique_dst_ports.add(pkt.dst_port)
                if pkt.flags: f.tcp_flags.append(pkt.flags)
                f.max_packet_size = max(f.max_packet_size, pkt.length)
                f.min_packet_size = min(f.min_packet_size, pkt.length)
                if f.packet_count >= FLOW_MAX_PKTS: self._emit(key)

    def _reaper(self):
        while not self._stop.is_set():
            time.sleep(FLOW_TIMEOUT)
            now = time.time()
            with self._lock:
                stale = [k for k,f in self._flows.items() if now-f.last_seen >= FLOW_TIMEOUT]
                for k in stale: self._emit(k)

    def _emit(self, key):
        f = self._flows.pop(key, None)
        if not f: return
        f.finalise()
        try: self.flow_q.put_nowait(f); self.emitted += 1
        except queue.Full: pass
