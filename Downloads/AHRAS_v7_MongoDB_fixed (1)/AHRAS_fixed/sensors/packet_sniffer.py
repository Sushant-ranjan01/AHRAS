"""
AHRAS — Packet Sniffer (Phase 1)
Captures live TCP/UDP/ICMP packets. Falls back to synthetic generator
if Scapy is unavailable or root privileges are missing.
"""
import time, queue, threading, random, logging, socket
from dataclasses import dataclass, field
from typing import Optional, Set

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from config import config
logger = logging.getLogger("ahras.sniffer")

def _get_local_ips() -> Set[str]:
    """Collect all IP addresses belonging to this machine."""
    ips = {"127.0.0.1", "::1", "0.0.0.0"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ips.add(info[4][0])
    except Exception:
        pass
    try:
        # Also grab via UDP trick (doesn't actually send anything)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return ips

# Computed once at import time
_LOCAL_IPS: Set[str] = _get_local_ips()

@dataclass
class RawPacket:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str       # TCP | UDP | ICMP | OTHER
    length: int
    timestamp: float = field(default_factory=time.time)
    flags: str = ""
    payload_size: int = 0

class PacketSniffer:
    def __init__(self, packet_queue: queue.Queue, interface: Optional[str] = None):
        self.packet_queue = packet_queue
        self.interface = interface or config.NETWORK_INTERFACE or None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.captured = 0
        self.dropped  = 0

    def start(self):
        target = self._sniff_loop if SCAPY_AVAILABLE else self._synthetic_loop
        self._thread = threading.Thread(target=target, daemon=True)
        self._thread.start()
        logger.info(f"PacketSniffer started (scapy={SCAPY_AVAILABLE})")

    def stop(self):
        self._stop.set()
        if self._thread: self._thread.join(timeout=3)

    # ── Real Scapy capture ────────────────────────────────────────────────────
    def _sniff_loop(self):
        kw = dict(prn=self._on_pkt, store=False, filter="ip",
                  stop_filter=lambda _: self._stop.is_set())
        if self.interface: kw["iface"] = self.interface
        try:
            sniff(**kw)
        except Exception as e:
            logger.warning(f"Scapy error ({e}) — switching to synthetic")
            self._synthetic_loop()

    def _on_pkt(self, pkt):
        try:
            if IP not in pkt: return
            ip = pkt[IP]
            # Skip traffic where BOTH src and dst are local — pure loopback/self noise
            if ip.src in _LOCAL_IPS and ip.dst in _LOCAL_IPS:
                return
            raw = RawPacket(src_ip=ip.src, dst_ip=ip.dst, src_port=0, dst_port=0,
                            protocol="OTHER", length=len(pkt), payload_size=len(bytes(ip.payload)))
            if TCP in pkt:
                raw.protocol = "TCP"; raw.src_port = pkt[TCP].sport
                raw.dst_port = pkt[TCP].dport; raw.flags = str(pkt[TCP].flags)
            elif UDP in pkt:
                raw.protocol = "UDP"; raw.src_port = pkt[UDP].sport; raw.dst_port = pkt[UDP].dport
            elif ICMP in pkt:
                raw.protocol = "ICMP"
            try:   self.packet_queue.put_nowait(raw); self.captured += 1
            except queue.Full: self.dropped += 1
        except Exception: pass

    # ── Synthetic fallback ────────────────────────────────────────────────────
    def _synthetic_loop(self):
        NORMAL = ["13.107.137.11","52.114.128.10","8.8.8.8","1.1.1.1",
                  "104.21.4.50","172.217.3.110","10.0.1.138","192.168.1.105"]
        ATTACK = ["185.220.101.45","45.33.32.156","198.20.69.74","23.45.67.89"]

        port_scan_active = False; scan_ctr = 0
        flood_active = False;     flood_ctr = 0

        while not self._stop.is_set():
            r = random.random()
            if r < 0.008: port_scan_active = True; scan_ctr = 0
            if r < 0.004: flood_active = True;     flood_ctr = 0

            if port_scan_active:
                pkt = RawPacket(src_ip=random.choice(ATTACK), dst_ip="10.0.1.138",
                                src_port=random.randint(1024,65535), dst_port=scan_ctr,
                                protocol="TCP", length=64, flags="S")
                scan_ctr += 1
                if scan_ctr > 100: port_scan_active = False
            elif flood_active:
                pkt = RawPacket(src_ip=random.choice(ATTACK), dst_ip="10.0.1.138",
                                src_port=random.randint(1024,65535), dst_port=80,
                                protocol="UDP", length=1400)
                flood_ctr += 1
                if flood_ctr > 300: flood_active = False
            else:
                proto = random.choice(["TCP","TCP","TCP","UDP","ICMP"])
                pkt = RawPacket(
                    src_ip=random.choice(NORMAL),
                    dst_ip=random.choice(["10.0.1.138","192.168.1.105"]),
                    src_port=random.randint(1024,65535),
                    dst_port=random.choice([80,443,53,22,8080,3306,3389]),
                    protocol=proto, length=random.randint(64,1500))
            try:   self.packet_queue.put_nowait(pkt); self.captured += 1
            except queue.Full: self.dropped += 1
            time.sleep(random.uniform(0.02, 0.2))
