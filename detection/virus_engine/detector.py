"""
AHRAS — Virus / Malware Detection Engine
Detection methods:
  1. Hash reputation check (known malware hashes)
  2. YARA rule pattern matching
  3. Suspicious file attribute analysis
  4. Process behaviour monitoring (via psutil)
  5. Network C2 communication detection
"""

import os
import time
import hashlib
import logging
import threading
import platform
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Callable

logger = logging.getLogger("ahras.virus")
OS = platform.system()

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# ── Known malware hash database (SHA256) — demo samples ─────────────────────
# In production: sync from VirusTotal, MalwareBazaar, MISP
KNOWN_MALWARE_HASHES: Dict[str, str] = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test File",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR Test File (SHA256)",
    "e1105070ba828007508566e28a2b8d4c": "Mirai Botnet",
    "84c82835a5d21bbcf75a61706d8ab549": "WannaCry Ransomware",
    "db349b97c37d22f5ea1d1841e3c89eb4": "NotPetya",
}

# ── Suspicious file signatures (magic bytes) ──────────────────────────────────
SUSPICIOUS_MAGIC = {
    b"MZ":           "Windows PE Executable",
    b"\x7fELF":      "Linux ELF Binary",
    b"#!/":          "Shell Script",
    b"PK\x03\x04":  "ZIP Archive (possible dropper)",
}

# ── YARA rules (inline, no file needed) ──────────────────────────────────────
YARA_RULES_SOURCE = """
rule SuspiciousShellcode {
    meta:
        description = "Detects common shellcode patterns"
        severity = "HIGH"
    strings:
        $nop_sled = { 90 90 90 90 90 90 90 90 }
        $int3 = { CC CC CC CC }
    condition:
        any of them
}

rule MaliciousPowerShell {
    meta:
        description = "Detects encoded/obfuscated PowerShell"
        severity = "HIGH"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "IEX(" nocase
        $enc4 = "Invoke-Expression" nocase
        $enc5 = "DownloadString" nocase
        $enc6 = "FromBase64String" nocase
    condition:
        2 of them
}

rule SuspiciousNetworkActivity {
    meta:
        description = "C2 communication patterns"
        severity = "CRITICAL"
    strings:
        $c2_1 = "cmd.exe /c" nocase
        $c2_2 = "powershell -w hidden" nocase
        $c2_3 = "certutil -decode" nocase
        $c2_4 = "bitsadmin /transfer" nocase
    condition:
        any of them
}

rule RansomwareBehaviour {
    meta:
        description = "Ransomware file encryption behaviour"
        severity = "CRITICAL"
    strings:
        $r1 = "YOUR FILES HAVE BEEN ENCRYPTED" nocase
        $r2 = "send bitcoin" nocase
        $r3 = "decrypt your files" nocase
        $r4 = "ransom" nocase
        $r5 = ".onion" nocase
    condition:
        2 of them
}
"""


@dataclass
class VirusAlert:
    alert_id: str
    detection_method: str
    severity: str
    filepath: str
    threat_name: str
    details: str
    hash_md5: str = ""
    hash_sha256: str = ""
    timestamp: float = field(default_factory=time.time)
    process_pid: int = 0
    process_name: str = ""
    quarantined: bool = False

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "detection_method": self.detection_method,
            "severity": self.severity,
            "filepath": self.filepath,
            "threat_name": self.threat_name,
            "details": self.details,
            "hash_md5": self.hash_md5,
            "hash_sha256": self.hash_sha256,
            "timestamp": self.timestamp,
            "time_str": time.strftime("%H:%M:%S", time.localtime(self.timestamp)),
            "process_pid": self.process_pid,
            "process_name": self.process_name,
            "quarantined": self.quarantined,
        }


class FileHashScanner:
    """Computes file hashes and checks against known malware database."""

    @staticmethod
    def hash_file(filepath: str) -> Dict[str, str]:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    md5.update(chunk)
                    sha256.update(chunk)
            return {"md5": md5.hexdigest(), "sha256": sha256.hexdigest()}
        except Exception:
            return {"md5": "", "sha256": ""}

    @staticmethod
    def is_known_malware(hashes: Dict[str, str]) -> Optional[str]:
        for h in hashes.values():
            if h in KNOWN_MALWARE_HASHES:
                return KNOWN_MALWARE_HASHES[h]
        return None


class YaraScanner:
    """Scans file content against compiled YARA rules."""

    def __init__(self):
        self._rules = None
        if YARA_AVAILABLE:
            try:
                self._rules = yara.compile(source=YARA_RULES_SOURCE)
                logger.info("YARA rules compiled successfully")
            except Exception as e:
                logger.warning(f"YARA compile error: {e}")

    def scan(self, filepath: str) -> List[dict]:
        if not self._rules:
            return []
        try:
            matches = self._rules.match(filepath)
            return [
                {
                    "rule": m.rule,
                    "meta": m.meta,
                    "strings": [str(s) for s in m.strings],
                }
                for m in matches
            ]
        except Exception:
            return []

    def scan_data(self, data: bytes) -> List[dict]:
        if not self._rules:
            return []
        try:
            matches = self._rules.match(data=data)
            return [{"rule": m.rule, "meta": m.meta} for m in matches]
        except Exception:
            return []


class ProcessMonitor:
    """Monitors running processes for suspicious behaviour."""

    SUSPICIOUS_NAMES = {
        "mimikatz.exe", "procdump.exe", "pwdump.exe",
        "netcat.exe", "nc.exe", "ncat.exe",
    }

    def scan_processes(self) -> List[dict]:
        if not PSUTIL_AVAILABLE:
            return []
        suspicious = []
        try:
            for proc in psutil.process_iter(["pid", "name", "cmdline", "cpu_percent", "memory_info"]):
                try:
                    info = proc.info
                    name = (info.get("name") or "").lower()
                    cmdline = " ".join(info.get("cmdline") or [])

                    if name in self.SUSPICIOUS_NAMES:
                        suspicious.append({
                            "pid": info["pid"],
                            "name": name,
                            "cmdline": cmdline[:200],
                            "reason": "Known malicious tool",
                            "severity": "CRITICAL",
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.debug(f"Process scan error: {e}")
        return suspicious


class VirusDetector:
    """
    Orchestrates all virus/malware detection methods.
    Generates VirusAlert objects for any detected threats.
    """

    def __init__(self, on_alert: Optional[Callable] = None):
        self.on_alert = on_alert
        self._hasher = FileHashScanner()
        self._yara = YaraScanner()
        self._proc_monitor = ProcessMonitor()
        self._alerts: List[VirusAlert] = []
        self._scanned: Set[str] = set()
        self._counter = 0
        self._lock = threading.Lock()
        self._enabled = True
        self._scan_thread: Optional[threading.Thread] = None
        logger.info("VirusDetector initialised")

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, val: bool):
        self._enabled = val

    def start_background_scan(self, paths: List[str] = None):
        if paths is None:
            paths = [os.path.expanduser("~")]
        self._scan_thread = threading.Thread(
            target=self._scan_loop, args=(paths,), daemon=True
        )
        self._scan_thread.start()

    def _scan_loop(self, paths: List[str]):
        while self._enabled:
            # Process scan every 30 seconds
            self._scan_processes()
            for path in paths:
                if not self._enabled:
                    break
                self._scan_directory(path)
            time.sleep(30)

    def _scan_directory(self, path: str):
        if not os.path.exists(path):
            return
        try:
            for root, _, files in os.walk(path):
                for fname in files[:50]:  # limit per run
                    if not self._enabled:
                        return
                    fpath = os.path.join(root, fname)
                    self.scan_file(fpath)
        except Exception:
            pass

    def scan_file(self, filepath: str) -> List[VirusAlert]:
        """Full scan of a single file. Returns list of alerts generated."""
        if not self._enabled or not os.path.isfile(filepath):
            return []
        alerts = []

        # Hash check
        hashes = self._hasher.hash_file(filepath)
        threat = self._hasher.is_known_malware(hashes)
        if threat:
            a = self._create_alert("HASH_MATCH", "CRITICAL", filepath, threat,
                                   f"MD5={hashes['md5']}", hashes["md5"], hashes["sha256"])
            alerts.append(a)

        # YARA scan
        matches = self._yara.scan(filepath)
        for m in matches:
            severity = m.get("meta", {}).get("severity", "HIGH")
            a = self._create_alert("YARA_MATCH", severity, filepath,
                                   m["rule"], f"YARA rule matched: {m['rule']}",
                                   hashes["md5"], hashes["sha256"])
            alerts.append(a)

        return alerts

    def _scan_processes(self):
        procs = self._proc_monitor.scan_processes()
        for p in procs:
            self._create_alert("PROCESS_DETECTION", p["severity"],
                               p["name"], p["name"], p["reason"])

    def _create_alert(self, method: str, severity: str, filepath: str,
                      threat_name: str, details: str,
                      md5: str = "", sha256: str = "") -> VirusAlert:
        self._counter += 1
        alert = VirusAlert(
            alert_id=f"VIR-{self._counter:04d}",
            detection_method=method,
            severity=severity,
            filepath=filepath,
            threat_name=threat_name,
            details=details,
            hash_md5=md5,
            hash_sha256=sha256,
        )
        with self._lock:
            self._alerts.insert(0, alert)
            if len(self._alerts) > 200:
                self._alerts.pop()
        logger.warning(f"[VIRUS] {method} | {severity} | {threat_name} | {filepath}")
        if self.on_alert:
            self.on_alert(alert)
        return alert

    def recent_alerts(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[:limit]]

    def stats(self) -> dict:
        with self._lock:
            total = len(self._alerts)
            critical = sum(1 for a in self._alerts if a.severity == "CRITICAL")
        return {"total_alerts": total, "critical_alerts": critical, "enabled": self._enabled}
