"""
AHRAS v4 — Threat Hunting Module
Allows SOC analysts to pivot on any indicator (IP, domain, URL, hash, MITRE)
and get back correlated results from alerts, cases, threat intel, and risk scores.
"""

import re
import time
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

logger = logging.getLogger("ahras.threat_hunting")


@dataclass
class HuntResult:
    query: str
    query_type: str  # ip | domain | url | hash | mitre
    alerts: List[Dict] = field(default_factory=list)
    cases: List[Dict] = field(default_factory=list)
    threat_intel: Dict = field(default_factory=dict)
    risk_score: Optional[float] = None
    risk_severity: str = "UNKNOWN"
    mitre_techniques: List[Dict] = field(default_factory=list)
    ioc_matches: List[Dict] = field(default_factory=list)
    total_hits: int = 0
    hunt_duration_ms: float = 0.0
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "query": self.query,
            "query_type": self.query_type,
            "alerts": self.alerts,
            "cases": self.cases,
            "threat_intel": self.threat_intel,
            "risk_score": self.risk_score,
            "risk_severity": self.risk_severity,
            "mitre_techniques": self.mitre_techniques,
            "ioc_matches": self.ioc_matches,
            "total_hits": self.total_hits,
            "hunt_duration_ms": round(self.hunt_duration_ms, 2),
            "timestamp": self.timestamp,
        }


def _detect_type(query: str) -> str:
    """Auto-detect the indicator type from the string."""
    q = query.strip()
    # IPv4
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", q):
        return "ip"
    # MD5 / SHA1 / SHA256
    if re.match(r"^[a-fA-F0-9]{32}$", q) or re.match(r"^[a-fA-F0-9]{40}$", q) or re.match(r"^[a-fA-F0-9]{64}$", q):
        return "hash"
    # MITRE Txxxx
    if re.match(r"^T\d{4}(\.\d{3})?$", q, re.IGNORECASE):
        return "mitre"
    # URL
    if q.startswith("http://") or q.startswith("https://") or "/" in q:
        return "url"
    # Default: domain
    return "domain"


class ThreatHunter:
    """
    Cross-correlates an indicator across all AHRAS data sources:
      - Event / Alert store
      - Case management
      - Threat Intel feed
      - IOC database
      - MITRE mapping
      - Risk engine
    """

    def __init__(self):
        # References injected after init to avoid circular imports
        self._alert_mgr = None
        self._case_mgr = None
        self._threat_intel = None
        self._ioc_mgr = None
        self._mitre = None
        self._risk_engine = None
        self._event_mgr = None
        logger.info("ThreatHunter initialised")

    # ── Dependency injection ─────────────────────────────────────────────────

    def inject(self, *, alert_mgr=None, case_mgr=None, threat_intel=None,
               ioc_mgr=None, mitre=None, risk_engine=None, event_mgr=None):
        if alert_mgr:   self._alert_mgr   = alert_mgr
        if case_mgr:    self._case_mgr    = case_mgr
        if threat_intel: self._threat_intel = threat_intel
        if ioc_mgr:     self._ioc_mgr     = ioc_mgr
        if mitre:       self._mitre       = mitre
        if risk_engine: self._risk_engine  = risk_engine
        if event_mgr:   self._event_mgr   = event_mgr

    # ── Public hunt methods ──────────────────────────────────────────────────

    def hunt(self, query: str, query_type: str = "auto") -> HuntResult:
        """
        Universal hunt: pass any indicator and optionally specify the type.
        Type auto-detection works for most common formats.
        """
        t0 = time.time()
        query = query.strip()
        if query_type == "auto":
            query_type = _detect_type(query)

        result = HuntResult(
            query=query,
            query_type=query_type,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        )

        dispatch = {
            "ip":     self._hunt_ip,
            "domain": self._hunt_domain,
            "url":    self._hunt_url,
            "hash":   self._hunt_hash,
            "mitre":  self._hunt_mitre,
        }
        fn = dispatch.get(query_type, self._hunt_generic)
        fn(query, result)

        result.total_hits = (
            len(result.alerts) + len(result.cases) +
            len(result.ioc_matches) + len(result.mitre_techniques) +
            (1 if result.threat_intel else 0)
        )
        result.hunt_duration_ms = (time.time() - t0) * 1000
        logger.info(f"Hunt [{query_type}] '{query}' → {result.total_hits} hits in {result.hunt_duration_ms:.1f}ms")
        return result

    def hunt_ip(self, ip: str) -> HuntResult:
        return self.hunt(ip, "ip")

    def hunt_domain(self, domain: str) -> HuntResult:
        return self.hunt(domain, "domain")

    def hunt_url(self, url: str) -> HuntResult:
        return self.hunt(url, "url")

    def hunt_hash(self, file_hash: str) -> HuntResult:
        return self.hunt(file_hash, "hash")

    def hunt_mitre(self, technique_id: str) -> HuntResult:
        return self.hunt(technique_id, "mitre")

    # ── Internal hunt handlers ───────────────────────────────────────────────

    def _hunt_ip(self, ip: str, result: HuntResult):
        self._collect_alerts(result, ip_filter=ip)
        self._collect_cases(result, ip_filter=ip)
        self._collect_threat_intel_ip(result, ip)
        self._collect_iocs(result, ip)
        self._collect_risk(result, ip)

    def _hunt_domain(self, domain: str, result: HuntResult):
        self._collect_alerts(result, domain_filter=domain)
        self._collect_cases(result, domain_filter=domain)
        self._collect_threat_intel_domain(result, domain)
        self._collect_iocs(result, domain)

    def _hunt_url(self, url: str, result: HuntResult):
        # Extract domain from URL for broader matching
        domain = re.sub(r"https?://([^/]+).*", r"\1", url)
        self._collect_alerts(result, domain_filter=domain)
        self._collect_cases(result, domain_filter=domain)
        self._collect_iocs(result, url)
        self._collect_iocs(result, domain)

    def _hunt_hash(self, file_hash: str, result: HuntResult):
        self._collect_alerts(result, hash_filter=file_hash)
        self._collect_cases(result, hash_filter=file_hash)
        if self._threat_intel and hasattr(self._threat_intel, "check_hash"):
            try:
                ti = self._threat_intel.check_hash(file_hash)
                if ti:
                    result.threat_intel = ti if isinstance(ti, dict) else {"result": str(ti)}
            except Exception as e:
                logger.warning(f"TI hash lookup failed: {e}")
        self._collect_iocs(result, file_hash)

    def _hunt_mitre(self, technique_id: str, result: HuntResult):
        self._collect_alerts(result, mitre_filter=technique_id)
        self._collect_cases(result, mitre_filter=technique_id)
        if self._mitre:
            try:
                mapping = self._mitre.get_technique(technique_id)
                if mapping:
                    result.mitre_techniques = [mapping] if isinstance(mapping, dict) else mapping
            except Exception as e:
                logger.warning(f"MITRE lookup failed: {e}")

    def _hunt_generic(self, query: str, result: HuntResult):
        self._collect_alerts(result, generic_filter=query)
        self._collect_cases(result, generic_filter=query)
        self._collect_iocs(result, query)

    # ── Data collectors ──────────────────────────────────────────────────────

    def _collect_alerts(self, result: HuntResult, ip_filter=None, domain_filter=None,
                        hash_filter=None, mitre_filter=None, generic_filter=None):
        if not self._alert_mgr:
            return
        try:
            raw = []
            if hasattr(self._alert_mgr, "get_alerts"):
                raw = self._alert_mgr.get_alerts(limit=500) or []
            elif hasattr(self._alert_mgr, "alerts"):
                raw = list(self._alert_mgr.alerts.values())

            for alert in raw:
                a = alert.to_dict() if hasattr(alert, "to_dict") else (alert if isinstance(alert, dict) else {})
                text = str(a).lower()
                match = False
                if ip_filter and ip_filter in text:
                    match = True
                if domain_filter and domain_filter.lower() in text:
                    match = True
                if hash_filter and hash_filter.lower() in text:
                    match = True
                if mitre_filter and mitre_filter.upper() in str(a).upper():
                    match = True
                if generic_filter and generic_filter.lower() in text:
                    match = True
                if match:
                    result.alerts.append(a)
                if len(result.alerts) >= 50:
                    break
        except Exception as e:
            logger.warning(f"Alert collection failed: {e}")

    def _collect_cases(self, result: HuntResult, ip_filter=None, domain_filter=None,
                       hash_filter=None, mitre_filter=None, generic_filter=None):
        if not self._case_mgr:
            return
        try:
            raw = []
            if hasattr(self._case_mgr, "list_cases"):
                raw = self._case_mgr.list_cases() or []
            elif hasattr(self._case_mgr, "cases"):
                raw = list(self._case_mgr.cases.values())

            for case in raw:
                c = case.to_dict() if hasattr(case, "to_dict") else (case if isinstance(case, dict) else {})
                text = str(c).lower()
                match = any([
                    ip_filter and ip_filter in text,
                    domain_filter and domain_filter.lower() in text,
                    hash_filter and hash_filter.lower() in text,
                    mitre_filter and mitre_filter.upper() in str(c).upper(),
                    generic_filter and generic_filter.lower() in text,
                ])
                if match:
                    result.cases.append(c)
                if len(result.cases) >= 20:
                    break
        except Exception as e:
            logger.warning(f"Case collection failed: {e}")

    def _collect_threat_intel_ip(self, result: HuntResult, ip: str):
        if not self._threat_intel:
            return
        try:
            if hasattr(self._threat_intel, "check_ip"):
                ti = self._threat_intel.check_ip(ip)
            elif hasattr(self._threat_intel, "lookup"):
                ti = self._threat_intel.lookup(ip)
            else:
                return
            if ti:
                result.threat_intel = ti if isinstance(ti, dict) else {"result": str(ti)}
        except Exception as e:
            logger.warning(f"TI IP lookup failed: {e}")

    def _collect_threat_intel_domain(self, result: HuntResult, domain: str):
        if not self._threat_intel:
            return
        try:
            if hasattr(self._threat_intel, "check_domain"):
                ti = self._threat_intel.check_domain(domain)
            elif hasattr(self._threat_intel, "lookup"):
                ti = self._threat_intel.lookup(domain)
            else:
                return
            if ti:
                result.threat_intel = ti if isinstance(ti, dict) else {"result": str(ti)}
        except Exception as e:
            logger.warning(f"TI domain lookup failed: {e}")

    def _collect_iocs(self, result: HuntResult, indicator: str):
        if not self._ioc_mgr:
            return
        try:
            if hasattr(self._ioc_mgr, "check_ioc"):
                hit = self._ioc_mgr.check_ioc(indicator)
                if hit:
                    entry = hit if isinstance(hit, dict) else {"indicator": indicator, "result": str(hit)}
                    if entry not in result.ioc_matches:
                        result.ioc_matches.append(entry)
        except Exception as e:
            logger.warning(f"IOC check failed: {e}")

    def _collect_risk(self, result: HuntResult, ip: str):
        if not self._risk_engine:
            return
        try:
            # Build a minimal detection dict for scoring
            det = {
                "src_ip": ip, "attack_type": "Normal", "confidence": 0.5,
                "packet_count": 0, "anomaly_flag": False,
            }
            r = self._risk_engine.evaluate(det)
            result.risk_score = r.risk_score_100
            result.risk_severity = r.severity
        except Exception as e:
            logger.warning(f"Risk collection failed: {e}")
