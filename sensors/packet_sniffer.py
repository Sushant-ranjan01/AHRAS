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

def _autodetect_interface() -> Optional[str]:
    """scapy's default interface (conf.iface) is picked by an internal
    heuristic that is frequently WRONG on machines with many virtual NPF
    adapters (VPN clients, VMware/VirtualBox, Bluetooth PAN, loopback,
    Npcap loopback, etc). That's the #1 cause of 'admin + Npcap installed
    but still 0 packets captured'. Instead, find the interface whose IP
    actually matches the one this machine uses to reach the internet."""
    if not SCAPY_AVAILABLE:
        return None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        return None
    try:
        import platform
        if platform.system() == "Windows":
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                if local_ip in (iface.get("ips") or []):
                    name = iface.get("name")
                    logger.info(
                        f"Auto-detected active network interface: "
                        f"{iface.get('name')} ({iface.get('description', iface.get('name'))}) "
                        f"matching local IP {local_ip}"
                    )
                    return name
        else:
            from scapy.all import get_if_list, get_if_addr
            for name in get_if_list():
                try:
                    if get_if_addr(name) == local_ip:
                        logger.info(f"Auto-detected active network interface: {name} (IP {local_ip})")
                        return name
                except Exception:
                    continue
    except Exception as e:
        logger.warning(f"Interface auto-detection failed: {e}")
    return None

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
        # Priority: explicit arg > .env NETWORK_INTERFACE > auto-detected
        # active adapter > None (let scapy fall back to its own default,
        # which is unreliable — see _autodetect_interface above).
        self.interface = interface or config.NETWORK_INTERFACE or _autodetect_interface()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.captured = 0
        self.dropped  = 0

    WATCHDOG_SECONDS = 8  # how long to wait for real capture before deciding it isn't working

    def start(self):
        if not SCAPY_AVAILABLE:
            logger.error(
                "scapy is not installed/importable — real packet capture is "
                "unavailable. Install it with: pip install scapy (and on "
                "Windows, also install Npcap from https://npcap.com/ in "
                "'WinPcap API-compatible mode')."
            )
            if config.SYNTHETIC_FALLBACK_ENABLED:
                logger.warning("SYNTHETIC_FALLBACK_ENABLED=true — generating synthetic demo traffic instead.")
                self._thread = threading.Thread(target=self._synthetic_loop, daemon=True)
                self._thread.start()
            else:
                logger.warning("SYNTHETIC_FALLBACK_ENABLED=false — no traffic will be captured until this is fixed.")
            return

        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        logger.info(f"PacketSniffer started (scapy={SCAPY_AVAILABLE}, interface={self.interface or 'default'})")
        threading.Thread(target=self._watchdog, daemon=True).start()

    def _watchdog(self):
        time.sleep(self.WATCHDOG_SECONDS)
        if self._stop.is_set() or self.captured > 0:
            return
        try:
            from scapy.all import get_if_list
            ifaces = get_if_list()
        except Exception:
            ifaces = []
        logger.error(
            f"No packets captured via scapy in {self.WATCHDOG_SECONDS}s. This "
            "almost always means one of: (1) the app isn't running with "
            "Administrator/root privileges, (2) Npcap isn't installed "
            "(Windows), or (3) NETWORK_INTERFACE in .env points at the wrong "
            f"adapter. Available interfaces: {ifaces or 'could not list — scapy/Npcap issue'}"
        )
        if config.SYNTHETIC_FALLBACK_ENABLED:
            logger.warning("SYNTHETIC_FALLBACK_ENABLED=true — starting synthetic demo traffic as a fallback.")
            threading.Thread(target=self._synthetic_loop, daemon=True).start()

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
            logger.error(
                f"Scapy capture error: {e}. Common causes: not running as "
                "Administrator/root, Npcap not installed (Windows), or an "
                "invalid NETWORK_INTERFACE value in .env."
            )
            if config.SYNTHETIC_FALLBACK_ENABLED:
                logger.warning("SYNTHETIC_FALLBACK_ENABLED=true — switching to synthetic demo traffic.")
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
