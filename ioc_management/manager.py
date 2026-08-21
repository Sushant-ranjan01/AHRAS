"""AHRAS — IOC (Indicators of Compromise) Manager
Manages a database of IPs, domains, hashes, URLs, emails that analysts
can query and add custom IOCs to.
"""
import time
import uuid
import threading
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum

logger = logging.getLogger("ahras.ioc")


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"
    CVE = "cve"


class IOCThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class IOCEntry:
    ioc_id: str
    indicator: str
    ioc_type: IOCType
    threat_level: IOCThreatLevel
    description: str
    tags: List[str]
    source: str
    added_by: str
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    hit_count: int = 0
    active: bool = True
    mitre_technique: str = ""

    def to_dict(self) -> dict:
        return {
            "ioc_id": self.ioc_id,
            "indicator": self.indicator,
            "ioc_type": self.ioc_type.value,
            "threat_level": self.threat_level.value,
            "description": self.description,
            "tags": self.tags,
            "source": self.source,
            "added_by": self.added_by,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.created_at)),
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_seen)),
            "hit_count": self.hit_count,
            "active": self.active,
            "mitre_technique": self.mitre_technique,
        }


# ── Seed IOC database ──────────────────────────────────────────────────────────

_SEED_IOCS = [
    ("185.220.101.1",  IOCType.IP,     IOCThreatLevel.CRITICAL, "TOR Exit Node",         ["tor", "anonymizer"],             "TorProject"),
    ("45.33.32.156",   IOCType.IP,     IOCThreatLevel.HIGH,     "Shodan Mass Scanner",   ["scanner", "recon"],              "Shodan"),
    ("80.82.77.33",    IOCType.IP,     IOCThreatLevel.HIGH,     "Shodan Crawler",        ["scanner"],                       "Shodan"),
    ("198.20.70.114",  IOCType.IP,     IOCThreatLevel.MEDIUM,   "Mass Scanner",          ["scanner", "recon"],              "AbuseIPDB"),
    ("5.188.86.172",   IOCType.IP,     IOCThreatLevel.CRITICAL, "Botnet C2 Server",      ["botnet", "c2", "malware"],       "Internal"),
    ("malware.test",   IOCType.DOMAIN, IOCThreatLevel.CRITICAL, "Known Malware Domain",  ["malware", "c2"],                 "Internal"),
    ("phishing.test",  IOCType.DOMAIN, IOCThreatLevel.HIGH,     "Phishing Domain",       ["phishing", "credential"],        "PhishTank"),
    ("44d88612fea8a8f36de82e1278abb02f", IOCType.HASH, IOCThreatLevel.LOW, "EICAR Test File", ["test", "av"], "EICAR"),
    ("http://malware.test/payload.exe", IOCType.URL, IOCThreatLevel.CRITICAL, "Malware Payload URL", ["malware", "download"], "Internal"),
    ("admin@phishing.test", IOCType.EMAIL, IOCThreatLevel.HIGH, "Phishing Email", ["phishing"], "SpamHaus"),
]


class IOCManager:
    """Thread-safe IOC database with matching capabilities."""

    def __init__(self):
        from database import IOCRepository
        self._repo = IOCRepository()
        self._repo.load_from_mongo(limit=10000)
        self._iocs: Dict[str, IOCEntry] = {}
        self._lock = threading.Lock()
        self._seed()
        logger.info(f"IOCManager ready — {len(self._iocs)} IOCs loaded")

    def _seed(self):
        for indicator, ioc_type, threat_level, desc, tags, source in _SEED_IOCS:
            self._add(indicator, ioc_type, threat_level, desc, tags, source, "system", "")

    def _add(self, indicator: str, ioc_type: IOCType, threat_level: IOCThreatLevel,
             description: str, tags: List[str], source: str, added_by: str,
             mitre_technique: str) -> IOCEntry:
        entry = IOCEntry(
            ioc_id=str(uuid.uuid4())[:12],
            indicator=indicator.lower().strip(),
            ioc_type=ioc_type,
            threat_level=threat_level,
            description=description,
            tags=tags,
            source=source,
            added_by=added_by,
            mitre_technique=mitre_technique,
        )
        self._iocs[entry.ioc_id] = entry
        try:
            self._repo.save(entry.to_dict() if hasattr(entry, 'to_dict') else vars(entry))
        except Exception:
            pass
        return entry

    # ── Public API ─────────────────────────────────────────────────────────────

    def add_ioc(self, indicator: str, ioc_type: str, threat_level: str,
                description: str, tags: List[str], source: str,
                added_by: str, mitre_technique: str = "") -> IOCEntry:
        with self._lock:
            entry = self._add(
                indicator, IOCType(ioc_type), IOCThreatLevel(threat_level),
                description, tags, source, added_by, mitre_technique
            )
        logger.info(f"IOC added: {indicator} ({ioc_type}) by {added_by}")
        return entry

    def match(self, indicator: str) -> Optional[IOCEntry]:
        """Check if an indicator matches any active IOC."""
        indicator_lower = indicator.lower().strip()
        with self._lock:
            for entry in self._iocs.values():
                if entry.active and (
                    entry.indicator == indicator_lower or
                    indicator_lower.endswith(entry.indicator) or
                    entry.indicator in indicator_lower
                ):
                    entry.hit_count += 1
                    entry.last_seen = time.time()
                    return entry
        return None

    def match_ip(self, ip: str) -> Optional[IOCEntry]:
        entry = self.match(ip)
        if entry and entry.ioc_type == IOCType.IP:
            return entry
        return None

    def list_iocs(self, ioc_type: str = None, active_only: bool = True) -> List[dict]:
        with self._lock:
            results = []
            for entry in self._iocs.values():
                if active_only and not entry.active:
                    continue
                if ioc_type and entry.ioc_type.value != ioc_type:
                    continue
                results.append(entry.to_dict())
            return sorted(results, key=lambda x: x["created_at"], reverse=True)

    def get_ioc(self, ioc_id: str) -> Optional[dict]:
        with self._lock:
            entry = self._iocs.get(ioc_id)
            return entry.to_dict() if entry else None

    def delete_ioc(self, ioc_id: str, deleted_by: str) -> bool:
        with self._lock:
            if ioc_id in self._iocs:
                self._iocs[ioc_id].active = False
                logger.info(f"IOC {ioc_id} deactivated by {deleted_by}")
                return True
        return False

    def stats(self) -> dict:
        with self._lock:
            by_type = {}
            by_level = {}
            total_hits = 0
            for entry in self._iocs.values():
                if entry.active:
                    t = entry.ioc_type.value
                    l = entry.threat_level.value
                    by_type[t] = by_type.get(t, 0) + 1
                    by_level[l] = by_level.get(l, 0) + 1
                    total_hits += entry.hit_count
            return {
                "total": len([e for e in self._iocs.values() if e.active]),
                "by_type": by_type,
                "by_level": by_level,
                "total_hits": total_hits,
            }

    def top_hit_iocs(self, n: int = 10) -> List[dict]:
        with self._lock:
            sorted_iocs = sorted(
                [e for e in self._iocs.values() if e.active and e.hit_count > 0],
                key=lambda x: x.hit_count, reverse=True
            )
            return [e.to_dict() for e in sorted_iocs[:n]]
