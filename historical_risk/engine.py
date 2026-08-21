"""
AHRAS v6 — Historical Risk Engine
===================================
Tracks every IP, domain, and hash that has ever appeared in AHRAS events,
alerts, and cases. When the Risk Engine evaluates a new event, it can query
the historical risk engine to add a recidivism boost:

  "This IP was involved in 15 past incidents → Risk += 15"

This is the research contribution: most risk engines are memoryless —
every event is scored in isolation. AHRAS gives repeat offenders a higher
score automatically, matching real analyst intuition.

Data Stored (all in-memory, keyed by indicator):
  - Total appearances in events
  - Total appearances in alerts
  - Total incident involvements (cases)
  - Highest risk score ever seen
  - First seen / last seen timestamps
  - MITRE techniques observed historically
  - Associated usernames, ports, paths

Score Contribution Formula:
  incident_boost  = min(30, incident_count × 2)     # max 30 pts
  alert_boost     = min(15, alert_count)             # max 15 pts
  recency_factor  = 1.0 if seen < 7 days ago else 0.5
  history_score   = (incident_boost + alert_boost) × recency_factor
"""

import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from datetime import datetime, timezone

logger = logging.getLogger("ahras.historical_risk")

MAX_HISTORY_PER_INDICATOR = 500   # cap stored event references


@dataclass
class IndicatorHistory:
    """Full history record for a single indicator (IP, domain, hash, etc.)."""
    indicator: str
    indicator_type: str            # ip | domain | hash | url | username
    first_seen: float = field(default_factory=time.time)
    last_seen: float  = field(default_factory=time.time)

    # Occurrence counts
    event_count:    int = 0
    alert_count:    int = 0
    incident_count: int = 0        # cases linked to this indicator

    # Risk history
    max_risk_score: float = 0.0
    avg_risk_score: float = 0.0
    _risk_scores: List[float] = field(default_factory=list, repr=False)

    # Context collected across all events
    seen_attack_types:   Set[str] = field(default_factory=set)
    seen_mitre_techniques: Set[str] = field(default_factory=set)
    seen_severities:     Set[str] = field(default_factory=set)
    associated_ips:      Set[str] = field(default_factory=set)   # other IPs seen same event
    associated_users:    Set[str] = field(default_factory=set)
    associated_ports:    Set[int] = field(default_factory=set)

    # Recent raw events (capped)
    recent_events: List[dict] = field(default_factory=list, repr=False)

    def record_event(self, event: dict, risk_score: float = 0.0):
        """Update history with a new event."""
        now = time.time()
        self.last_seen = now
        self.event_count += 1

        if risk_score > 0:
            self._risk_scores.append(risk_score)
            if risk_score > self.max_risk_score:
                self.max_risk_score = risk_score
            self.avg_risk_score = sum(self._risk_scores) / len(self._risk_scores)

        at = event.get("attack_type") or event.get("event_type", "")
        if at and at != "Normal":
            self.seen_attack_types.add(at)

        mt = event.get("mitre_technique", "")
        if mt:
            self.seen_mitre_techniques.add(mt)

        sev = event.get("severity", "")
        if sev:
            self.seen_severities.add(sev)

        for field_name in ("dst_ip", "peer_ip"):
            ip = event.get(field_name, "")
            if ip and ip != self.indicator:
                self.associated_ips.add(ip)

        user = event.get("username", event.get("user", ""))
        if user:
            self.associated_users.add(user)

        port = event.get("dst_port") or event.get("src_port")
        if port:
            try:
                self.associated_ports.add(int(port))
            except (TypeError, ValueError):
                pass

        snapshot = {
            "timestamp": datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "attack_type": at,
            "risk_score": round(risk_score, 1),
            "severity": sev,
        }
        self.recent_events.append(snapshot)
        if len(self.recent_events) > MAX_HISTORY_PER_INDICATOR:
            self.recent_events = self.recent_events[-MAX_HISTORY_PER_INDICATOR:]

    def record_alert(self):
        self.alert_count += 1

    def record_incident(self):
        self.incident_count += 1

    def days_since_last_seen(self) -> float:
        return (time.time() - self.last_seen) / 86400

    def calculate_history_boost(self) -> float:
        """
        Calculate the risk boost this indicator earns based on its history.

        Formula:
          incident_boost = min(30, incident_count × 2)
          alert_boost    = min(15, alert_count)
          recency_factor = 1.0 if seen < 7 days ago, 0.5 if 7–30d, 0.25 if >30d
          history_score  = (incident_boost + alert_boost) × recency_factor
        """
        days = self.days_since_last_seen()
        if days < 7:
            recency = 1.0
        elif days < 30:
            recency = 0.5
        else:
            recency = 0.25

        incident_boost = min(30.0, self.incident_count * 2.0)
        alert_boost    = min(15.0, float(self.alert_count))
        raw_boost      = incident_boost + alert_boost
        return round(raw_boost * recency, 2)

    def threat_profile(self) -> str:
        """Return a one-line human-readable threat profile."""
        if self.incident_count == 0 and self.alert_count == 0:
            return "No prior incidents or alerts."
        parts = []
        if self.incident_count:
            parts.append(f"{self.incident_count} incident{'s' if self.incident_count != 1 else ''}")
        if self.alert_count:
            parts.append(f"{self.alert_count} alert{'s' if self.alert_count != 1 else ''}")
        if self.seen_attack_types:
            parts.append(f"attack types: {', '.join(sorted(self.seen_attack_types))}")
        if self.seen_mitre_techniques:
            parts.append(f"MITRE: {', '.join(sorted(self.seen_mitre_techniques))}")
        days = self.days_since_last_seen()
        parts.append(f"last seen {days:.1f}d ago")
        return " | ".join(parts)

    def to_dict(self) -> dict:
        return {
            "indicator":             self.indicator,
            "indicator_type":        self.indicator_type,
            "first_seen":            datetime.fromtimestamp(self.first_seen, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "last_seen":             datetime.fromtimestamp(self.last_seen,  tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "days_since_last_seen":  round(self.days_since_last_seen(), 1),
            "event_count":           self.event_count,
            "alert_count":           self.alert_count,
            "incident_count":        self.incident_count,
            "max_risk_score":        round(self.max_risk_score, 1),
            "avg_risk_score":        round(self.avg_risk_score, 1),
            "history_boost":         self.calculate_history_boost(),
            "threat_profile":        self.threat_profile(),
            "seen_attack_types":     sorted(self.seen_attack_types),
            "seen_mitre_techniques": sorted(self.seen_mitre_techniques),
            "seen_severities":       sorted(self.seen_severities),
            "associated_ips":        sorted(self.associated_ips)[:20],
            "associated_users":      sorted(self.associated_users)[:20],
            "associated_ports":      sorted(self.associated_ports)[:20],
            "recent_events":         self.recent_events[-10:],
        }


class HistoricalRiskEngine:
    """
    Maintains a history store of all indicators seen by AHRAS.
    Called by the main analysis pipeline after every event and alert.

    Key methods:
      record_event(event, risk_score)   → update indicator history
      record_alert(indicator)           → mark an alert for this indicator
      record_incident(indicator)        → mark a case for this indicator
      get_boost(indicator)              → float: risk points to add
      get_history(indicator)            → IndicatorHistory or None
      top_repeat_offenders(n)           → list of highest-history indicators
    """

    def __init__(self):
        self._store: Dict[str, IndicatorHistory] = {}
        self._lock  = threading.Lock()
        self._stats = {"total_indicators": 0, "total_events": 0,
                       "total_alerts": 0, "total_incidents": 0}
        from database import HistoricalRiskRepository
        self._repo = HistoricalRiskRepository()
        self._repo.load_from_mongo(limit=20000)
        logger.info("HistoricalRiskEngine initialised (MongoDB-backed)")

    # ── Primary API ──────────────────────────────────────────────────────────

    def record_event(self, event: dict, risk_score: float = 0.0):
        """
        Record an event in the history store.
        Extracts src_ip, domain, username from the event dict automatically.
        """
        with self._lock:
            self._stats["total_events"] += 1
            # Extract all indicators from the event
            indicators = []
            src_ip = event.get("src_ip", "")
            if src_ip:
                indicators.append((src_ip, "ip"))
            domain = event.get("domain", event.get("hostname", ""))
            if domain and "." in domain:
                indicators.append((domain, "domain"))
            username = event.get("username", event.get("user", ""))
            if username:
                indicators.append((username, "username"))
            file_hash = event.get("file_hash", event.get("hash", ""))
            if file_hash:
                indicators.append((file_hash, "hash"))

            for indicator, itype in indicators:
                if not indicator or len(indicator) > 256:
                    continue
                key = f"{itype}:{indicator}"
                if key not in self._store:
                    self._store[key] = IndicatorHistory(
                        indicator=indicator, indicator_type=itype
                    )
                    self._stats["total_indicators"] += 1
                self._store[key].record_event(event, risk_score)
                try:
                    d = self._store[key].to_dict()
                    d["indicator_key"] = key
                    self._repo.save(d)
                except Exception:
                    pass

    def record_alert(self, indicator: str, indicator_type: str = "ip"):
        with self._lock:
            key = f"{indicator_type}:{indicator}"
            if key in self._store:
                self._store[key].record_alert()
                self._stats["total_alerts"] += 1

    def record_incident(self, indicator: str, indicator_type: str = "ip"):
        with self._lock:
            key = f"{indicator_type}:{indicator}"
            if key in self._store:
                self._store[key].record_incident()
                self._stats["total_incidents"] += 1

    def get_boost(self, indicator: str, indicator_type: str = "ip") -> float:
        """Return the history-based risk boost for this indicator (0–45 pts)."""
        with self._lock:
            key = f"{indicator_type}:{indicator}"
            h = self._store.get(key)
            return h.calculate_history_boost() if h else 0.0

    def get_history(self, indicator: str,
                    indicator_type: str = "ip") -> Optional[IndicatorHistory]:
        with self._lock:
            return self._store.get(f"{indicator_type}:{indicator}")

    def get_history_dict(self, indicator: str,
                         indicator_type: str = "ip") -> Optional[dict]:
        h = self.get_history(indicator, indicator_type)
        return h.to_dict() if h else None

    def get_all_risk_series(self, indicator_type: str = "ip",
                            min_events: int = 3) -> Dict[str, List[float]]:
        """Returns {indicator: [risk_score, ...]} for every tracked
        indicator of the given type with at least min_events events.
        Used by forecast.AttackPredictor for fleet-wide trend analysis."""
        with self._lock:
            out = {}
            for key, h in self._store.items():
                if h.indicator_type != indicator_type:
                    continue
                scores = [e.get("risk_score", 0.0) for e in h.recent_events if "risk_score" in e]
                if len(scores) >= min_events:
                    out[h.indicator] = scores
            return out

    def top_repeat_offenders(self, n: int = 20,
                             indicator_type: str = None) -> List[dict]:
        """Return the top-N indicators by history boost (highest first)."""
        with self._lock:
            records = list(self._store.values())
        if indicator_type:
            records = [r for r in records if r.indicator_type == indicator_type]
        records.sort(key=lambda r: r.calculate_history_boost(), reverse=True)
        return [r.to_dict() for r in records[:n]]

    def top_by_incidents(self, n: int = 20) -> List[dict]:
        with self._lock:
            records = sorted(self._store.values(),
                             key=lambda r: r.incident_count, reverse=True)
        return [r.to_dict() for r in records[:n]]

    def search(self, query: str) -> List[dict]:
        """Search history by partial indicator match."""
        q = query.lower().strip()
        with self._lock:
            matches = [
                h.to_dict() for h in self._store.values()
                if q in h.indicator.lower()
            ]
        return sorted(matches, key=lambda x: x["history_boost"], reverse=True)[:50]

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def summary(self) -> dict:
        """Dashboard-ready summary."""
        with self._lock:
            records = list(self._store.values())
        if not records:
            return {"total_indicators": 0, "top_offenders": []}
        top = sorted(records, key=lambda r: r.calculate_history_boost(), reverse=True)
        return {
            "total_indicators":  len(records),
            "total_events":      self._stats["total_events"],
            "total_alerts":      self._stats["total_alerts"],
            "total_incidents":   self._stats["total_incidents"],
            "top_5_offenders":   [r.to_dict() for r in top[:5]],
            "ips_tracked":       sum(1 for r in records if r.indicator_type == "ip"),
            "domains_tracked":   sum(1 for r in records if r.indicator_type == "domain"),
            "hashes_tracked":    sum(1 for r in records if r.indicator_type == "hash"),
            "users_tracked":     sum(1 for r in records if r.indicator_type == "username"),
        }
