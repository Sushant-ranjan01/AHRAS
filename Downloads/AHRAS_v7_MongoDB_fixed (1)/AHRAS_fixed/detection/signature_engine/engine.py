"""AHRAS — Enhanced Signature Detection Engine v3.0
Added: DNS Tunneling, Beaconing, C2 Detection, Web Attacks,
       Lateral Movement, Data Exfiltration, Credential Attacks
"""
import time, logging, threading, math
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional, Dict, Deque, List
from sensors.flow_generator import FlowRecord
from config import config

logger = logging.getLogger("ahras.signature")

@dataclass
class SignatureResult:
    attack_type: str; confidence: float; severity: str; rule_id: str; details: str

class _Rate:
    def __init__(self, window=60.0):
        self.window=window; self._e: Dict[str,deque]=defaultdict(deque); self._l=threading.Lock()
    def record(self, k):
        now=time.time()
        with self._l:
            d=self._e[k]; d.append(now); cut=now-self.window
            while d and d[0]<cut: d.popleft()
            return len(d)
    def count(self, k) -> int:
        with self._l: return len(self._e.get(k, []))

class _BeaconTracker:
    """Detects regular-interval C2 beacon traffic."""
    def __init__(self, window=300.0, min_intervals=5):
        self._times: Dict[str,deque] = defaultdict(lambda: deque(maxlen=30))
        self._window = window
        self._min_intervals = min_intervals
        self._lock = threading.Lock()

    def record(self, key: str) -> float:
        """Returns regularity score 0-1 (1=highly regular = beacon)."""
        now = time.time()
        with self._lock:
            d = self._times[key]
            d.append(now)
            cutoff = now - self._window
            while d and d[0] < cutoff:
                d.popleft()
            if len(d) < self._min_intervals:
                return 0.0
            intervals = [d[i+1]-d[i] for i in range(len(d)-1)]
            if not intervals:
                return 0.0
            mean = sum(intervals) / len(intervals)
            if mean < 1.0:
                return 0.0
            variance = sum((x-mean)**2 for x in intervals) / len(intervals)
            cv = math.sqrt(variance) / mean  # coefficient of variation
            # Low CV = very regular = beacon
            regularity = max(0.0, 1.0 - cv * 2)
            return regularity

class SignatureEngine:
    def __init__(self):
        self._ssh   = _Rate(60)
        self._dns_q = _Rate(10)      # DNS query rate
        self._ftp   = _Rate(60)
        self._rdp   = _Rate(60)
        self._smb   = _Rate(60)
        self._http  = _Rate(10)
        self._scan_ports: Dict[str,set]  = defaultdict(set)
        self._scan_time:  Dict[str,float] = {}
        self._beacon  = _BeaconTracker(window=300, min_intervals=5)
        self._exfil_bytes: Dict[str,deque] = defaultdict(lambda: deque(maxlen=100))
        self._lateral_dsts: Dict[str,set] = defaultdict(set)
        self._lateral_time: Dict[str,float] = {}
        self._lock = threading.Lock()

    def analyse(self, flow: FlowRecord) -> SignatureResult:
        for rule in [
            self._dns_tunneling, self._dns_amp,
            self._ssh_bf, self._rdp_bf, self._ftp_bf, self._smb_bf,
            self._port_scan, self._lateral_movement,
            self._data_exfil, self._beaconing,
            self._udp_flood, self._flood, self._web_attack, self._high_rate
        ]:
            r = rule(flow)
            if r: return r
        return SignatureResult("Normal", 1.0, "LOW", "none", "No match")

    # ── Original Rules ────────────────────────────────────────────────────────

    def _port_scan(self, flow):
        src=flow.src_ip; now=time.time()
        if now - self._scan_time.get(src,0) > 30:
            self._scan_ports[src]=set(); self._scan_time[src]=now
        self._scan_ports[src].update(flow.unique_dst_ports)
        u=len(self._scan_ports[src])
        if u >= config.PORT_SCAN_THRESHOLD:
            sev="CRITICAL" if u>config.PORT_SCAN_THRESHOLD*3 else "HIGH" if u>config.PORT_SCAN_THRESHOLD*2 else "MEDIUM"
            return SignatureResult("Port Scan", min(u/config.PORT_SCAN_THRESHOLD,1.0), sev, "SIG-001", f"{src} probed {u} ports")

    def _flood(self, flow):
        if flow.packets_per_second >= config.FLOOD_THRESHOLD:
            return SignatureResult("Traffic Flood", 1.0, "CRITICAL", "SIG-002", f"PPS={flow.packets_per_second:.0f}")

    def _udp_flood(self, flow):
        if flow.protocol=="UDP" and flow.packets_per_second > config.FLOOD_THRESHOLD*0.3 and flow.unique_ports<=3:
            return SignatureResult("UDP Flood", 0.85, "HIGH", "SIG-003", f"UDP PPS={flow.packets_per_second:.0f}")

    def _dns_amp(self, flow):
        if flow.protocol=="UDP" and flow.dst_port==53 and flow.avg_packet_size>512 and flow.packets_per_second>5:
            return SignatureResult("DNS Amplification", 0.80, "CRITICAL", "SIG-004", f"UDP/53 avg={flow.avg_packet_size:.0f}B")

    def _ssh_bf(self, flow):
        if flow.protocol=="TCP" and flow.dst_port==22:
            c=self._ssh.record(flow.src_ip)
            if c >= config.SSH_BRUTEFORCE_THRESHOLD:
                return SignatureResult("SSH Bruteforce", min(c/config.SSH_BRUTEFORCE_THRESHOLD,1.0), "HIGH", "SIG-005", f"{flow.src_ip} SSH attempts={c}")

    def _high_rate(self, flow):
        t=config.FLOOD_THRESHOLD*0.2
        if flow.packets_per_second > t:
            return SignatureResult("High Packet Rate", 0.65, "MEDIUM", "SIG-006", f"PPS={flow.packets_per_second:.0f}")

    # ── NEW: DNS Tunneling ────────────────────────────────────────────────────

    def _dns_tunneling(self, flow):
        """Detect DNS tunneling: high query rate + large packet sizes to port 53."""
        if flow.protocol != "UDP" or flow.dst_port != 53:
            return None
        rate = self._dns_q.record(flow.src_ip)
        # DNS tunneling: high query rate OR very large DNS packets
        if rate >= 20 or (flow.avg_packet_size > 200 and rate >= 8):
            conf = min(0.5 + rate / 40, 0.95)
            return SignatureResult(
                "DNS Tunneling", conf, "HIGH", "SIG-010",
                f"{flow.src_ip} DNS queries={rate}/10s avg_size={flow.avg_packet_size:.0f}B"
            )

    # ── NEW: Beaconing (C2) ───────────────────────────────────────────────────

    def _beaconing(self, flow):
        """Detect regular-interval outbound connections (C2 beacon pattern)."""
        key = f"{flow.src_ip}:{flow.dst_ip}:{flow.dst_port}"
        regularity = self._beacon.record(key)
        if regularity >= 0.75:
            return SignatureResult(
                "Beaconing", regularity, "HIGH", "SIG-011",
                f"{flow.src_ip}→{flow.dst_ip}:{flow.dst_port} regularity={regularity:.2f} (C2 pattern)"
            )

    # ── NEW: RDP Brute Force ──────────────────────────────────────────────────

    def _rdp_bf(self, flow):
        if flow.protocol == "TCP" and flow.dst_port == 3389:
            c = self._rdp.record(flow.src_ip)
            if c >= config.SSH_BRUTEFORCE_THRESHOLD:
                return SignatureResult(
                    "Credential Attack", min(c / config.SSH_BRUTEFORCE_THRESHOLD, 1.0),
                    "HIGH", "SIG-012", f"{flow.src_ip} RDP attempts={c}"
                )

    # ── NEW: FTP Brute Force ──────────────────────────────────────────────────

    def _ftp_bf(self, flow):
        if flow.protocol == "TCP" and flow.dst_port == 21:
            c = self._ftp.record(flow.src_ip)
            if c >= config.SSH_BRUTEFORCE_THRESHOLD * 1.5:
                return SignatureResult(
                    "Credential Attack", min(c / (config.SSH_BRUTEFORCE_THRESHOLD * 1.5), 1.0),
                    "MEDIUM", "SIG-013", f"{flow.src_ip} FTP attempts={c}"
                )

    # ── NEW: SMB Brute Force ──────────────────────────────────────────────────

    def _smb_bf(self, flow):
        if flow.protocol == "TCP" and flow.dst_port in (445, 139):
            c = self._smb.record(flow.src_ip)
            if c >= config.SSH_BRUTEFORCE_THRESHOLD:
                return SignatureResult(
                    "Credential Attack", min(c / config.SSH_BRUTEFORCE_THRESHOLD, 1.0),
                    "HIGH", "SIG-014", f"{flow.src_ip} SMB attempts={c} (T1110)"
                )

    # ── NEW: Lateral Movement ─────────────────────────────────────────────────

    def _lateral_movement(self, flow):
        """Detect lateral movement: one source hitting many internal IPs on service ports."""
        LATERAL_PORTS = {22, 445, 139, 3389, 5985, 5986, 23, 21}
        if flow.dst_port not in LATERAL_PORTS:
            return None
        src = flow.src_ip
        # Only flag internal-to-internal or external→internal on service ports
        now = time.time()
        if now - self._lateral_time.get(src, 0) > 120:
            self._lateral_dsts[src] = set()
            self._lateral_time[src] = now
        self._lateral_dsts[src].add(flow.dst_ip)
        unique = len(self._lateral_dsts[src])
        if unique >= 4:
            return SignatureResult(
                "Lateral Movement", min(unique / 8, 1.0), "CRITICAL", "SIG-015",
                f"{src} connecting to {unique} hosts on port {flow.dst_port} (T1021)"
            )

    # ── NEW: Data Exfiltration ────────────────────────────────────────────────

    def _data_exfil(self, flow):
        """Detect large outbound data transfers (potential exfiltration)."""
        now = time.time()
        self._exfil_bytes[flow.src_ip].append((now, flow.byte_count))
        cutoff = now - 60
        recent = [(t, b) for t, b in self._exfil_bytes[flow.src_ip] if t >= cutoff]
        self._exfil_bytes[flow.src_ip] = deque(recent, maxlen=100)
        total_bytes = sum(b for _, b in recent)
        # 50MB+ in 60 seconds = suspicious
        if total_bytes > 50 * 1024 * 1024:
            conf = min(total_bytes / (200 * 1024 * 1024), 1.0)
            return SignatureResult(
                "Data Exfiltration", conf, "CRITICAL", "SIG-016",
                f"{flow.src_ip} sent {total_bytes/1024/1024:.1f}MB in 60s (T1041)"
            )

    # ── NEW: Web Attack Detection ─────────────────────────────────────────────

    def _web_attack(self, flow):
        """Detect web attacks on HTTP/HTTPS ports by packet patterns."""
        if flow.dst_port not in (80, 443, 8080, 8443):
            return None
        rate = self._http.record(f"{flow.src_ip}:{flow.dst_ip}")
        # High request rate + small packets = SQLi / scan
        if rate >= 30 and flow.avg_packet_size < 200:
            return SignatureResult(
                "Web Attack", min(rate / 50, 1.0), "HIGH", "SIG-017",
                f"{flow.src_ip} rapid HTTP requests={rate}/10s (SQLi/XSS/scan)"
            )
        # Very large packets on HTTP = potential upload / RCE
        if flow.avg_packet_size > 8192 and rate >= 5:
            return SignatureResult(
                "Web Attack", 0.70, "MEDIUM", "SIG-018",
                f"{flow.src_ip} large HTTP payloads avg={flow.avg_packet_size:.0f}B"
            )
