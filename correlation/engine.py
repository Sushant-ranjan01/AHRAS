"""AHRAS — Correlation Engine
Combines multiple related events into high-confidence incidents.
Port Scan + Brute Force + Exploit = CRITICAL Incident
Dramatically reduces false positives.
"""
import time
import uuid
import threading
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Deque, Optional, Tuple

logger = logging.getLogger("ahras.correlation")

# ── Correlation rules ─────────────────────────────────────────────────────────

@dataclass
class CorrelationRule:
    rule_id: str
    name: str
    description: str
    required_events: List[str]   # attack_types that must appear
    time_window: int             # seconds
    severity: str
    mitre_technique: str
    confidence_boost: float = 0.3


CORRELATION_RULES = [
    CorrelationRule(
        rule_id="COR-001",
        name="Reconnaissance → Exploitation Chain",
        description="Port scan followed by brute force — classic attack chain",
        required_events=["Port Scan", "SSH Bruteforce"],
        time_window=300, severity="CRITICAL",
        mitre_technique="T1595 → T1110", confidence_boost=0.4
    ),
    CorrelationRule(
        rule_id="COR-002",
        name="DDoS Compound Attack",
        description="Multiple flood vectors from same source",
        required_events=["Traffic Flood", "UDP Flood"],
        time_window=120, severity="CRITICAL",
        mitre_technique="T1498", confidence_boost=0.5
    ),
    CorrelationRule(
        rule_id="COR-003",
        name="Advanced Persistent Threat Pattern",
        description="Recon + C2 Beaconing — APT indicator",
        required_events=["Port Scan", "Anomalous Behaviour"],
        time_window=600, severity="CRITICAL",
        mitre_technique="T1046 → T1071", confidence_boost=0.45
    ),
    CorrelationRule(
        rule_id="COR-004",
        name="Credential Attack Escalation",
        description="Brute force followed by anomalous behavior — possible successful breach",
        required_events=["SSH Bruteforce", "Anomalous Behaviour"],
        time_window=180, severity="CRITICAL",
        mitre_technique="T1110 → T1071", confidence_boost=0.5
    ),
    CorrelationRule(
        rule_id="COR-005",
        name="Full Kill Chain Detected",
        description="Complete attack chain: Recon → Attack → C2",
        required_events=["Port Scan", "SSH Bruteforce", "Anomalous Behaviour"],
        time_window=900, severity="CRITICAL",
        mitre_technique="T1595 → T1110 → T1071", confidence_boost=0.6
    ),
    CorrelationRule(
        rule_id="COR-006",
        name="DNS Amplification DDoS",
        description="DNS amplification combined with traffic flood",
        required_events=["DNS Amplification", "Traffic Flood"],
        time_window=60, severity="CRITICAL",
        mitre_technique="T1498.002", confidence_boost=0.5
    ),
]


@dataclass
class CorrelatedIncident:
    incident_id: str
    rule: CorrelationRule
    src_ip: str
    matched_events: List[dict]
    severity: str
    confidence: float
    created_at: float = field(default_factory=time.time)
    acknowledged: bool = False

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "rule_id": self.rule.rule_id,
            "rule_name": self.rule.name,
            "description": self.rule.description,
            "src_ip": self.src_ip,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "mitre_technique": self.rule.mitre_technique,
            "event_count": len(self.matched_events),
            "event_ids": [e.get("event_id", "") for e in self.matched_events],
            "attack_types": list({e.get("attack_type", "") for e in self.matched_events}),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.created_at)),
            "acknowledged": self.acknowledged,
        }


class CorrelationEngine:
    """
    Sliding-window correlation engine.
    Tracks events per source IP and fires rules when attack chains are detected.
    """

    def __init__(self, max_incidents: int = 500):
        # Per-IP event history: ip -> deque of (timestamp, event_dict)
        self._ip_events: Dict[str, Deque[Tuple[float, dict]]] = defaultdict(lambda: deque(maxlen=200))
        self._incidents: List[CorrelatedIncident] = []
        self._fired: Dict[str, float] = {}  # rule+ip -> last_fired_ts (cooldown)
        self._lock = threading.Lock()
        self._max_incidents = max_incidents
        self._total_fired = 0
        logger.info(f"CorrelationEngine ready — {len(CORRELATION_RULES)} rules loaded")

    def ingest(self, event: dict) -> Optional[CorrelatedIncident]:
        """Ingest a new event and check all correlation rules. Returns incident if fired."""
        src_ip = event.get("src_ip", "")
        attack_type = event.get("attack_type", "Normal")
        if attack_type == "Normal" or not src_ip:
            return None

        now = time.time()

        with self._lock:
            # Append event to per-IP history
            self._ip_events[src_ip].append((now, event))

            # Check each rule
            for rule in CORRELATION_RULES:
                cooldown_key = f"{rule.rule_id}:{src_ip}"
                # 5-minute cooldown per rule per IP
                if now - self._fired.get(cooldown_key, 0) < 300:
                    continue

                # Gather events within the rule's time window
                cutoff = now - rule.time_window
                window_events = [e for ts, e in self._ip_events[src_ip] if ts >= cutoff]

                # Check if all required attack types are present
                seen_types = {e.get("attack_type", "") for e in window_events}
                if all(req in seen_types for req in rule.required_events):
                    # Fire the rule
                    self._fired[cooldown_key] = now
                    self._total_fired += 1

                    # Average confidence from matching events
                    base_conf = sum(e.get("confidence", 0.5) for e in window_events) / max(len(window_events), 1)
                    confidence = min(1.0, base_conf + rule.confidence_boost)

                    incident = CorrelatedIncident(
                        incident_id=f"INC-{str(uuid.uuid4())[:8].upper()}",
                        rule=rule,
                        src_ip=src_ip,
                        matched_events=list(window_events[-10:]),  # keep last 10
                        severity=rule.severity,
                        confidence=confidence,
                    )
                    self._incidents.insert(0, incident)
                    if len(self._incidents) > self._max_incidents:
                        self._incidents.pop()

                    logger.warning(
                        f"CORRELATION FIRED: {rule.name} — src={src_ip} "
                        f"conf={confidence:.2f} [{', '.join(rule.required_events)}]"
                    )
                    return incident

        return None

    def recent_incidents(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return [i.to_dict() for i in self._incidents[:limit]]

    def acknowledge(self, incident_id: str) -> bool:
        with self._lock:
            for inc in self._incidents:
                if inc.incident_id == incident_id:
                    inc.acknowledged = True
                    return True
        return False

    def stats(self) -> dict:
        with self._lock:
            total = len(self._incidents)
            unacked = sum(1 for i in self._incidents if not i.acknowledged)
            by_rule: Dict[str, int] = defaultdict(int)
            for inc in self._incidents:
                by_rule[inc.rule.name] += 1
            return {
                "total_incidents": total,
                "unacknowledged": unacked,
                "total_fired": self._total_fired,
                "by_rule": dict(by_rule),
                "rules_loaded": len(CORRELATION_RULES),
            }
