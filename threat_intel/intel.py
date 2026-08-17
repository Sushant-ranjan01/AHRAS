"""AHRAS — Threat Intelligence Manager
Integrates with AbuseIPDB, VirusTotal, AlienVault OTX for IP/domain/hash reputation.
Falls back to mock data when API keys are not configured.
"""
import time
import threading
import logging
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Optional, List
try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

logger = logging.getLogger("ahras.threat_intel")

@dataclass
class ThreatIntelResult:
    indicator: str
    indicator_type: str          # ip, domain, hash, url
    is_malicious: bool
    confidence: float            # 0-100
    source: str
    threat_types: List[str]
    country: str = ""
    isp: str = ""
    last_seen: str = ""
    reports: int = 0
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
            "source": self.source,
            "threat_types": self.threat_types,
            "country": self.country,
            "isp": self.isp,
            "last_seen": self.last_seen,
            "reports": self.reports,
        }


# ── Cache ─────────────────────────────────────────────────────────────────────

class _Cache:
    def __init__(self, ttl: int = 3600):
        self._data: Dict[str, tuple] = {}
        self._ttl = ttl
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[ThreatIntelResult]:
        with self._lock:
            if key in self._data:
                result, ts = self._data[key]
                if time.time() - ts < self._ttl:
                    return result
                del self._data[key]
        return None

    def set(self, key: str, result: ThreatIntelResult):
        with self._lock:
            self._data[key] = (result, time.time())

    def clear(self):
        with self._lock:
            self._data.clear()

    def size(self) -> int:
        with self._lock:
            return len(self._data)


# ── Known bad IPs for demo (simulates threat feed) ────────────────────────────

_KNOWN_BAD_IPS = {
    "185.220.101.1": ("TOR Exit Node", ["Anonymization", "Proxy"]),
    "45.33.32.156": ("Shodan Scanner", ["Scanner", "Reconnaissance"]),
    "80.82.77.33": ("Shodan Scanner", ["Scanner"]),
    "198.20.70.114": ("Mass Scanner", ["Scanner", "Reconnaissance"]),
    "162.142.125.0": ("Censys Scanner", ["Scanner"]),
    "5.188.86.172": ("Botnet C2", ["Botnet", "C2", "Malware"]),
    "194.165.16.11": ("Spam Source", ["Spam", "Phishing"]),
    "91.108.4.1": ("Telegram Abuse", ["Spam"]),
    "103.75.190.1": ("DDoS Source", ["DDoS", "Botnet"]),
}

_KNOWN_BAD_DOMAINS = {
    "malware.test": (["Malware Distribution"], 95),
    "phishing.test": (["Phishing"], 90),
    "botnet-c2.test": (["C2", "Botnet"], 98),
    "evil.test": (["Malware"], 85),
}

_KNOWN_BAD_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": ("EICAR Test File", ["Test", "AV Test"]),
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": ("EICAR SHA256", ["Test"]),
}


class ThreatIntelManager:
    """
    Threat intelligence lookups with caching.
    Uses real APIs when keys are configured, falls back to simulation.
    """

    def __init__(self, abuseipdb_key: str = "", virustotal_key: str = "", otx_key: str = ""):
        self._abuseipdb_key = abuseipdb_key
        self._virustotal_key = virustotal_key
        self._otx_key = otx_key
        self._cache = _Cache(ttl=3600)
        self._lock = threading.Lock()
        self._stats = {"lookups": 0, "cache_hits": 0, "malicious_found": 0}
        logger.info("ThreatIntelManager ready")

    # ── Public API ─────────────────────────────────────────────────────────────

    def check_ip(self, ip: str) -> ThreatIntelResult:
        cached = self._cache.get(f"ip:{ip}")
        if cached:
            with self._lock:
                self._stats["cache_hits"] += 1
            return cached

        with self._lock:
            self._stats["lookups"] += 1

        result = self._lookup_ip(ip)
        self._cache.set(f"ip:{ip}", result)
        if result.is_malicious:
            with self._lock:
                self._stats["malicious_found"] += 1
        return result

    def check_domain(self, domain: str) -> ThreatIntelResult:
        cached = self._cache.get(f"domain:{domain}")
        if cached:
            return cached
        result = self._lookup_domain(domain)
        self._cache.set(f"domain:{domain}", result)
        return result

    def check_hash(self, file_hash: str) -> ThreatIntelResult:
        cached = self._cache.get(f"hash:{file_hash}")
        if cached:
            return cached
        result = self._lookup_hash(file_hash)
        self._cache.set(f"hash:{file_hash}", result)
        return result

    def check_url(self, url: str) -> ThreatIntelResult:
        cached = self._cache.get(f"url:{url}")
        if cached:
            return cached
        result = self._lookup_url(url)
        self._cache.set(f"url:{url}", result)
        return result

    def stats(self) -> dict:
        with self._lock:
            return {**self._stats, "cache_size": self._cache.size()}

    # ── Lookups ────────────────────────────────────────────────────────────────

    def _lookup_ip(self, ip: str) -> ThreatIntelResult:
        # Try AbuseIPDB first
        if self._abuseipdb_key and REQUESTS_OK:
            try:
                r = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={"Key": self._abuseipdb_key, "Accept": "application/json"},
                    timeout=5
                )
                if r.status_code == 200:
                    data = r.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    return ThreatIntelResult(
                        indicator=ip, indicator_type="ip",
                        is_malicious=score >= 25,
                        confidence=float(score),
                        source="AbuseIPDB",
                        threat_types=data.get("usageType", "").split(",") if data.get("usageType") else [],
                        country=data.get("countryCode", ""),
                        isp=data.get("isp", ""),
                        last_seen=data.get("lastReportedAt", "") or "",
                        reports=data.get("totalReports", 0),
                        raw=data
                    )
            except Exception as e:
                logger.debug(f"AbuseIPDB lookup failed: {e}")

        # Try AlienVault OTX
        if self._otx_key and REQUESTS_OK:
            try:
                r = requests.get(
                    f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                    headers={"X-OTX-API-KEY": self._otx_key},
                    timeout=5
                )
                if r.status_code == 200:
                    data = r.json()
                    pulse_count = data.get("pulse_info", {}).get("count", 0)
                    geo = data.get("base_indicator", {})
                    threat_types = []
                    for pulse in data.get("pulse_info", {}).get("pulses", [])[:3]:
                        threat_types.extend(pulse.get("tags", []))
                    return ThreatIntelResult(
                        indicator=ip, indicator_type="ip",
                        is_malicious=pulse_count > 0,
                        confidence=min(100.0, float(pulse_count * 15)),
                        source="AlienVault OTX",
                        threat_types=list(set(threat_types))[:5],
                        country=data.get("country_name", ""),
                        isp=data.get("asn", ""),
                        last_seen=data.get("base_indicator", {}).get("created", ""),
                        reports=pulse_count,
                        raw={"pulse_count": pulse_count},
                    )
            except Exception as e:
                logger.debug(f"OTX lookup failed: {e}")

        # Simulation fallback
        return self._simulate_ip(ip)

    def _simulate_ip(self, ip: str) -> ThreatIntelResult:
        """Simulate threat intel for demo purposes."""
        if ip in _KNOWN_BAD_IPS:
            desc, threats = _KNOWN_BAD_IPS[ip]
            return ThreatIntelResult(
                indicator=ip, indicator_type="ip",
                is_malicious=True, confidence=90.0,
                source="AHRAS-TI (Demo)", threat_types=threats,
                country="Unknown", isp=desc,
                last_seen=time.strftime("%Y-%m-%d"), reports=42
            )
        # Check private ranges
        private = any(ip.startswith(p) for p in ("10.", "192.168.", "172.", "127.", "::1"))
        if private:
            return ThreatIntelResult(
                indicator=ip, indicator_type="ip",
                is_malicious=False, confidence=0.0,
                source="AHRAS-TI", threat_types=[],
                country="Private", isp="Internal Network",
                last_seen="", reports=0
            )
        # Use hash of IP to deterministically assign some as "suspicious"
        h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
        if h % 20 == 0:  # ~5% of external IPs flagged
            return ThreatIntelResult(
                indicator=ip, indicator_type="ip",
                is_malicious=True, confidence=float(55 + (h % 35)),
                source="AHRAS-TI (Heuristic)", threat_types=["Scanner", "Suspicious"],
                country="Unknown", isp="Unknown ASN",
                last_seen=time.strftime("%Y-%m-%d"), reports=h % 15 + 1
            )
        return ThreatIntelResult(
            indicator=ip, indicator_type="ip",
            is_malicious=False, confidence=5.0,
            source="AHRAS-TI", threat_types=[],
            country="Unknown", isp="", last_seen="", reports=0
        )

    def _lookup_domain(self, domain: str) -> ThreatIntelResult:
        # 1. Try VirusTotal domain lookup
        if self._virustotal_key and REQUESTS_OK:
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": self._virustotal_key},
                    timeout=5
                )
                if r.status_code == 200:
                    data = r.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) or 1
                    categories = list(data.get("categories", {}).values())
                    return ThreatIntelResult(
                        indicator=domain, indicator_type="domain",
                        is_malicious=malicious > 0,
                        confidence=round(malicious / total * 100, 1),
                        source="VirusTotal",
                        threat_types=categories if categories else (["Malicious"] if malicious else []),
                        last_seen=str(data.get("last_analysis_date", "")),
                        reports=malicious,
                        raw=stats,
                    )
            except Exception as e:
                logger.debug(f"VT domain lookup failed: {e}")

        # 2. Try OTX domain lookup
        if self._otx_key and REQUESTS_OK:
            try:
                r = requests.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                    headers={"X-OTX-API-KEY": self._otx_key},
                    timeout=5
                )
                if r.status_code == 200:
                    data = r.json()
                    pulse_count = data.get("pulse_info", {}).get("count", 0)
                    threat_types = []
                    for pulse in data.get("pulse_info", {}).get("pulses", [])[:3]:
                        threat_types.extend(pulse.get("tags", []))
                    return ThreatIntelResult(
                        indicator=domain, indicator_type="domain",
                        is_malicious=pulse_count > 0,
                        confidence=min(100.0, float(pulse_count * 10)),
                        source="AlienVault OTX",
                        threat_types=list(set(threat_types))[:5],
                        reports=pulse_count,
                        raw={"pulse_count": pulse_count},
                    )
            except Exception as e:
                logger.debug(f"OTX domain lookup failed: {e}")

        # 3. Local known-bad fallback
        if domain in _KNOWN_BAD_DOMAINS:
            threats, score = _KNOWN_BAD_DOMAINS[domain]
            return ThreatIntelResult(
                indicator=domain, indicator_type="domain",
                is_malicious=True, confidence=float(score),
                source="AHRAS-TI", threat_types=threats,
                last_seen=time.strftime("%Y-%m-%d"), reports=10
            )
        return ThreatIntelResult(
            indicator=domain, indicator_type="domain",
            is_malicious=False, confidence=0.0,
            source="AHRAS-TI", threat_types=[]
        )

    def _lookup_hash(self, file_hash: str) -> ThreatIntelResult:
        h_lower = file_hash.lower()
        if h_lower in _KNOWN_BAD_HASHES:
            name, threats = _KNOWN_BAD_HASHES[h_lower]
            return ThreatIntelResult(
                indicator=file_hash, indicator_type="hash",
                is_malicious=True, confidence=100.0,
                source="AHRAS-TI", threat_types=threats,
                last_seen=time.strftime("%Y-%m-%d"), reports=999
            )
        # Try VirusTotal
        if self._virustotal_key and REQUESTS_OK:
            try:
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers={"x-apikey": self._virustotal_key},
                    timeout=5
                )
                if r.status_code == 200:
                    data = r.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) or 1
                    return ThreatIntelResult(
                        indicator=file_hash, indicator_type="hash",
                        is_malicious=malicious > 0,
                        confidence=round(malicious / total * 100, 1),
                        source="VirusTotal",
                        threat_types=list(data.get("popular_threat_classification", {}).get("suggested_threat_label", "").split(".")) if data.get("popular_threat_classification") else [],
                        last_seen=data.get("last_analysis_date", ""),
                        reports=malicious, raw=stats
                    )
            except Exception as e:
                logger.debug(f"VirusTotal lookup failed: {e}")

        return ThreatIntelResult(
            indicator=file_hash, indicator_type="hash",
            is_malicious=False, confidence=0.0,
            source="AHRAS-TI", threat_types=[]
        )

    def _lookup_url(self, url: str) -> ThreatIntelResult:
        # Try VirusTotal URL lookup
        if self._virustotal_key and REQUESTS_OK:
            try:
                import base64
                url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
                r = requests.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers={"x-apikey": self._virustotal_key},
                    timeout=5
                )
                if r.status_code == 200:
                    data = r.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) or 1
                    return ThreatIntelResult(
                        indicator=url, indicator_type="url",
                        is_malicious=malicious > 0,
                        confidence=round(malicious / total * 100, 1),
                        source="VirusTotal",
                        threat_types=["Malicious URL"] if malicious else [],
                        reports=malicious, raw=stats,
                    )
            except Exception as e:
                logger.debug(f"VT URL lookup failed: {e}")

        # Fallback: domain-based check
        for bad in _KNOWN_BAD_DOMAINS:
            if bad in url:
                return ThreatIntelResult(
                    indicator=url, indicator_type="url",
                    is_malicious=True, confidence=90.0,
                    source="AHRAS-TI", threat_types=["Malicious URL"],
                    last_seen=time.strftime("%Y-%m-%d"), reports=5
                )
        return ThreatIntelResult(
            indicator=url, indicator_type="url",
            is_malicious=False, confidence=0.0,
            source="AHRAS-TI", threat_types=[]
        )
