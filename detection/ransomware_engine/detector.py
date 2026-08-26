"""
AHRAS — Ransomware Detection Engine
Monitors file system behaviour for ransomware indicators:
  - Rapid file modifications (mass encryption)
  - Mass file renaming (extension changes)
  - High file entropy (encrypted content)
  - Suspicious process execution
  - Unusual disk activity patterns
"""

import os
import math
import time
import threading
import logging
import platform
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Deque

logger = logging.getLogger("ahras.ransomware")
OS = platform.system()

RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".enc", ".locked", ".crypto", ".crypt",
    ".locky", ".cerber", ".zepto", ".odin", ".aesir",
    ".wnry", ".wcry", ".wncry", ".wncryt",
    ".ryuk", ".maze", ".revil", ".sodinokibi",
}

SUSPICIOUS_PROCESSES = {
    "vssadmin.exe", "wbadmin.exe", "bcdedit.exe",
    "wmic.exe", "powershell.exe", "cmd.exe",
}

RANSOM_NOTE_NAMES = {
    "readme.txt", "how_to_decrypt.txt", "decrypt_instructions.txt",
    "your_files_are_encrypted.txt", "recover_files.html",
    "!!!_read_me_!!!.txt", "ransom.txt",
}


@dataclass
class RansomwareAlert:
    alert_id: str
    indicator: str
    severity: str
    path: str
    details: str
    timestamp: float = field(default_factory=time.time)
    process: str = ""

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "indicator": self.indicator,
            "severity": self.severity,
            "path": self.path,
            "details": self.details,
            "timestamp": self.timestamp,
            "process": self.process,
            "time_str": time.strftime("%H:%M:%S", time.localtime(self.timestamp)),
        }


class EntropyAnalyzer:
    """Measures Shannon entropy of file content. High entropy → likely encrypted."""

    @staticmethod
    def calculate(filepath: str, sample_bytes: int = 8192) -> float:
        try:
            with open(filepath, "rb") as f:
                data = f.read(sample_bytes)
            if not data:
                return 0.0
            freq = defaultdict(int)
            for b in data:
                freq[b] += 1
            entropy = 0.0
            length = len(data)
            for count in freq.values():
                p = count / length
                if p > 0:
                    entropy -= p * math.log2(p)
            return entropy  # max 8.0 for truly random data
        except Exception:
            return 0.0

    @staticmethod
    def is_suspicious(entropy: float) -> bool:
        return entropy > 7.2  # > 7.2 bits → likely encrypted/compressed


class FileActivityTracker:
    """Tracks file modification rates per directory / overall."""

    def __init__(self, window: float = 10.0):
        self.window = window
        self._events: Deque[float] = deque()
        self._extension_changes: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def record_modification(self, path: str):
        now = time.time()
        with self._lock:
            self._events.append(now)
            cutoff = now - self.window
            while self._events and self._events[0] < cutoff:
                self._events.popleft()

        ext = os.path.splitext(path)[1].lower()
        if ext in RANSOMWARE_EXTENSIONS:
            with self._lock:
                self._extension_changes[ext] += 1

    def modification_rate(self) -> float:
        """Files modified per second in current window."""
        with self._lock:
            return len(self._events) / self.window

    def suspicious_extension_count(self) -> int:
        with self._lock:
            return sum(self._extension_changes.values())


class RansomwareDetector:
    """
    Combines file system monitoring, entropy analysis, and behavioural
    heuristics to detect ransomware activity in real time.
    Generates RansomwareAlert objects consumed by the event manager.
    """

    MASS_MOD_THRESHOLD = 20  # files/sec
    ENTROPY_THRESHOLD = 7.2
    RENAME_THRESHOLD = 10    # suspicious extension renames in 30s

    def __init__(self, on_alert: Optional[Callable] = None):
        self.on_alert = on_alert
        self._tracker = FileActivityTracker(window=30.0)
        self._alerts: List[RansomwareAlert] = []
        self._alert_counter = 0
        self._lock = threading.Lock()
        self._enabled = True
        self._monitor_thread: Optional[threading.Thread] = None
        logger.info("RansomwareDetector initialised")

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, val: bool):
        self._enabled = val
        logger.info(f"RansomwareDetector {'enabled' if val else 'disabled'}")

    def start_monitoring(self, watch_paths: List[str] = None):
        """Start file system watch (uses watchdog if available, else polling)."""
        if watch_paths is None:
            watch_paths = self._default_watch_paths()

        self._monitor_thread = threading.Thread(
            target=self._poll_loop, args=(watch_paths,), daemon=True
        )
        self._monitor_thread.start()
        logger.info(f"Ransomware monitor watching: {watch_paths}")

    def _default_watch_paths(self) -> List[str]:
        if OS == "Windows":
            return [os.path.expanduser("~/Documents"), os.path.expanduser("~/Desktop")]
        return [os.path.expanduser("~/Documents"), "/tmp"]

    def _poll_loop(self, paths: List[str]):
        """Lightweight polling fallback for file system changes."""
        snapshots: Dict[str, float] = {}
        while self._enabled:
            for path in paths:
                if not os.path.exists(path):
                    continue
                try:
                    for root, _, files in os.walk(path):
                        for fname in files:
                            fpath = os.path.join(root, fname)
                            try:
                                mtime = os.path.getmtime(fpath)
                                if fpath in snapshots and mtime != snapshots[fpath]:
                                    self._check_file(fpath)
                                snapshots[fpath] = mtime
                            except OSError:
                                pass
                except Exception:
                    pass
            time.sleep(2.0)

    def _check_file(self, path: str):
        """Run all heuristics on a modified file."""
        if not self._enabled:
            return
        self._tracker.record_modification(path)

        fname = os.path.basename(path).lower()
        ext = os.path.splitext(path)[1].lower()

        # Ransom note detection
        if fname in RANSOM_NOTE_NAMES:
            self._raise_alert("RANSOM_NOTE", "CRITICAL", path,
                              f"Ransom note detected: {fname}")
            return

        # Suspicious extension
        if ext in RANSOMWARE_EXTENSIONS:
            self._raise_alert("SUSPICIOUS_EXTENSION", "HIGH", path,
                              f"File renamed to ransomware extension: {ext}")

        # Mass modification rate
        rate = self._tracker.modification_rate()
        if rate > self.MASS_MOD_THRESHOLD:
            self._raise_alert("MASS_MODIFICATION", "CRITICAL", path,
                              f"Mass file modification rate: {rate:.1f} files/sec")

        # Entropy analysis (only for files we can read quickly)
        if os.path.getsize(path) > 0:
            entropy = EntropyAnalyzer.calculate(path)
            if EntropyAnalyzer.is_suspicious(entropy):
                self._raise_alert("HIGH_ENTROPY", "HIGH", path,
                                  f"File entropy={entropy:.2f} (>7.2 indicates encryption)")

        # Suspicious extension rename count
        if self._tracker.suspicious_extension_count() > self.RENAME_THRESHOLD:
            self._raise_alert("MASS_RENAME", "CRITICAL", path,
                              f"Mass file renaming to ransomware extensions detected")

    def _raise_alert(self, indicator: str, severity: str, path: str, details: str):
        self._alert_counter += 1
        alert = RansomwareAlert(
            alert_id=f"RAN-{self._alert_counter:04d}",
            indicator=indicator,
            severity=severity,
            path=path,
            details=details,
        )
        with self._lock:
            self._alerts.insert(0, alert)
            if len(self._alerts) > 200:
                self._alerts.pop()
        logger.warning(f"[RANSOMWARE] {indicator} | {severity} | {details}")
        if self.on_alert:
            self.on_alert(alert)

    def check_process(self, process_name: str, cmdline: str = "") -> Optional[RansomwareAlert]:
        """Check if a process exhibits ransomware-like behaviour."""
        name = process_name.lower()
        if name in SUSPICIOUS_PROCESSES:
            # Specific dangerous command patterns
            suspicious_cmds = [
                "vssadmin delete shadows",
                "wbadmin delete",
                "bcdedit /set",
                "wmic shadowcopy delete",
                "disable recovery",
            ]
            for cmd in suspicious_cmds:
                if cmd in cmdline.lower():
                    self._alert_counter += 1
                    alert = RansomwareAlert(
                        alert_id=f"RAN-{self._alert_counter:04d}",
                        indicator="SUSPICIOUS_PROCESS",
                        severity="CRITICAL",
                        path=process_name,
                        details=f"Shadow copy/backup deletion attempt: {cmdline[:100]}",
                        process=process_name,
                    )
                    with self._lock:
                        self._alerts.insert(0, alert)
                    if self.on_alert:
                        self.on_alert(alert)
                    return alert
        return None

    def recent_alerts(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[:limit]]

    def stats(self) -> dict:
        with self._lock:
            total = len(self._alerts)
            critical = sum(1 for a in self._alerts if a.severity == "CRITICAL")
        return {
            "total_alerts": total,
            "critical_alerts": critical,
            "modification_rate": self._tracker.modification_rate(),
            "suspicious_renames": self._tracker.suspicious_extension_count(),
            "enabled": self._enabled,
        }
