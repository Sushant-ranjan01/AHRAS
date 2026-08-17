"""AHRAS v4.0 — SOAR (Security Orchestration, Automation and Response)
Automated playbooks: Risk>90 → Block IP → Create Case → Report → Notify

Playbooks:
  critical_auto_response  risk>=90  → block + case + report
  high_auto_monitor       risk>=70  → case + notify
  ioc_match_response      IOC hit   → block + case
  honeypot_response       honeypot  → block + IOC + case
  correlation_response    incident  → case + notify
"""
import time, uuid, threading, logging
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Optional
from collections import deque
logger = logging.getLogger("ahras.soar")

@dataclass
class PlaybookRun:
    run_id: str
    playbook: str
    trigger: str
    src_ip: str
    actions_taken: List[str]
    success: bool
    timestamp: float = field(default_factory=time.time)
    case_id: str = ""
    notes: str = ""

    def to_dict(self):
        return {
            "run_id":self.run_id,"playbook":self.playbook,"trigger":self.trigger,
            "src_ip":self.src_ip,"actions_taken":self.actions_taken,"success":self.success,
            "case_id":self.case_id,"notes":self.notes,
            "timestamp":time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(self.timestamp)),
        }


class SOAREngine:
    """
    Automated response playbooks.
    Inject service references after construction.
    """
    def __init__(self):
        self._runs: deque = deque(maxlen=1000)
        self._lock = threading.Lock()
        self._total = 0
        # Per-IP cooldown: don't fire same playbook for same IP more than once per N seconds
        self._cooldown: dict = {}          # key: (playbook, ip) → last_fired timestamp
        self.COOLDOWN_SECS = 600           # 10 minutes per IP per playbook
        # Services injected after startup
        self.firewall    = None
        self.case_mgr    = None
        self.ioc_mgr     = None
        self.alert_mgr   = None
        self.report_gen  = None
        self.evt_mgr     = None
        self.threat_graph = None
        logger.info("SOAREngine ready")

    def inject(self, firewall=None, case_mgr=None, ioc_mgr=None,
               alert_mgr=None, report_gen=None, evt_mgr=None, threat_graph=None):
        self.firewall=firewall; self.case_mgr=case_mgr; self.ioc_mgr=ioc_mgr
        self.alert_mgr=alert_mgr; self.report_gen=report_gen; self.evt_mgr=evt_mgr
        self.threat_graph=threat_graph

    def _graph_ingest_case(self, case, affected_ips):
        """Best-effort: feed a SOAR-created case into the threat graph."""
        if self.threat_graph is not None and case is not None:
            try:
                self.threat_graph.ingest_case(case.case_id, affected_ips or [])
            except Exception:
                pass

    # ── Playbook triggers ──────────────────────────────────────────────────────

    def on_high_risk(self, event: dict, risk_result) -> Optional[PlaybookRun]:
        """Triggered by analysis worker when risk>=70."""
        risk = risk_result.risk_score_100 if hasattr(risk_result,"risk_score_100") else risk_result.get("risk_score_100",0)
        src_ip = event.get("src_ip","")
        if risk < 70 or not src_ip:
            return None
        # Cooldown check — don't spam cases for the same IP
        playbook = "critical_auto_response" if risk >= 90 else "high_auto_monitor"
        key = (playbook, src_ip)
        now = time.time()
        with self._lock:
            last = self._cooldown.get(key, 0)
            if now - last < self.COOLDOWN_SECS:
                return None   # skip — already handled this IP recently
            self._cooldown[key] = now
        if risk >= 90:
            return self._run_critical(src_ip, event, risk)
        else:
            return self._run_high_monitor(src_ip, event, risk)

    def on_ioc_match(self, src_ip:str, ioc_entry, event:dict) -> Optional[PlaybookRun]:
        """Triggered when IOC match found."""
        key = ("ioc_match", src_ip)
        now = time.time()
        with self._lock:
            if now - self._cooldown.get(key, 0) < self.COOLDOWN_SECS:
                return None
            self._cooldown[key] = now
        return self._run_ioc_response(src_ip, ioc_entry, event)

    def on_honeypot_hit(self, hit) -> Optional[PlaybookRun]:
        """Triggered by honeypot hit."""
        src_ip = hit.src_ip if hasattr(hit, "src_ip") else str(hit)
        key = ("honeypot", src_ip)
        now = time.time()
        with self._lock:
            if now - self._cooldown.get(key, 0) < 300:  # 5 min for honeypot
                return None
            self._cooldown[key] = now
        return self._run_honeypot_response(hit)

    def on_correlation_incident(self, incident: dict) -> Optional[PlaybookRun]:
        """Triggered by correlation engine."""
        src_ip = incident.get("src_ip", "")
        rule = incident.get("rule_name", "")
        key = ("correlation", src_ip, rule)
        now = time.time()
        with self._lock:
            if now - self._cooldown.get(key, 0) < self.COOLDOWN_SECS:
                return None
            self._cooldown[key] = now
        return self._run_correlation_response(incident)

    # ── Playbooks ──────────────────────────────────────────────────────────────

    def _run_critical(self, src_ip, event, risk) -> PlaybookRun:
        actions = []
        case_id = ""

        # 1. Block IP
        if self.firewall:
            try:
                self.firewall.block_ip(src_ip, f"SOAR auto-block risk={risk:.0f}", "soar")
                actions.append(f"BLOCKED {src_ip}")
            except Exception as e:
                actions.append(f"Block failed: {e}")

        # 2. Create Case
        if self.case_mgr:
            try:
                case = self.case_mgr.create_case(
                    title=f"[SOAR] Critical Risk from {src_ip}",
                    description=f"Automated response triggered. Risk={risk:.0f}/100\n"
                                f"Attack: {event.get('attack_type','Unknown')}\n"
                                f"MITRE: {event.get('mitre_technique','-')}",
                    priority="CRITICAL", created_by="soar",
                    attack_type=event.get("attack_type",""),
                    affected_ips=[src_ip],
                    mitre_technique=event.get("mitre_technique",""),
                    mitre_tactic=event.get("mitre_tactic",""),
                    tags=["soar","auto-block","critical"]
                )
                case_id = case.case_id
                self._graph_ingest_case(case, [src_ip])
                actions.append(f"CASE created: {case_id}")
            except Exception as e:
                actions.append(f"Case failed: {e}")

        # 3. Notify
        if self.alert_mgr:
            try:
                self.alert_mgr._push_notification(
                    "SOAR", f"SOAR-{src_ip}",
                    f"🤖 Auto-blocked {src_ip} (risk={risk:.0f}). Case: {case_id}"
                )
                actions.append("NOTIFICATION sent")
            except Exception as e:
                actions.append(f"Notify failed: {e}")

        return self._record("critical_auto_response", f"risk={risk:.0f}", src_ip, actions, True, case_id)

    def _run_high_monitor(self, src_ip, event, risk) -> PlaybookRun:
        actions = []; case_id = ""
        if self.case_mgr:
            try:
                case = self.case_mgr.create_case(
                    title=f"[SOAR] High Risk Activity from {src_ip}",
                    description=f"Risk={risk:.0f}/100. Attack: {event.get('attack_type','Unknown')}",
                    priority="HIGH", created_by="soar",
                    attack_type=event.get("attack_type",""),
                    affected_ips=[src_ip], tags=["soar","high-risk"]
                )
                case_id = case.case_id
                self._graph_ingest_case(case, [src_ip])
                actions.append(f"CASE created: {case_id}")
            except Exception as e:
                actions.append(f"Case failed: {e}")
        if self.alert_mgr:
            try:
                self.alert_mgr._push_notification(
                    "SOAR", f"SOAR-HIGH-{src_ip}",
                    f"🔶 High risk {src_ip} (risk={risk:.0f}) — case {case_id} opened"
                )
                actions.append("NOTIFICATION sent")
            except Exception as e:
                actions.append(f"Notify failed: {e}")
        return self._record("high_auto_monitor", f"risk={risk:.0f}", src_ip, actions, True, case_id)

    def _run_ioc_response(self, src_ip, ioc, event) -> PlaybookRun:
        actions = []; case_id = ""
        if self.firewall:
            try:
                self.firewall.block_ip(src_ip, f"SOAR IOC match: {ioc.indicator}", "soar")
                actions.append(f"BLOCKED {src_ip} (IOC match)")
            except Exception as e:
                actions.append(f"Block failed: {e}")
        if self.case_mgr:
            try:
                case = self.case_mgr.create_case(
                    title=f"[SOAR] IOC Match: {src_ip}",
                    description=f"IOC matched: {ioc.indicator} ({ioc.threat_level.value})\nDesc: {ioc.description}",
                    priority="HIGH", created_by="soar",
                    affected_ips=[src_ip], tags=["soar","ioc-match"]
                )
                case_id = case.case_id
                self._graph_ingest_case(case, [src_ip])
                actions.append(f"CASE created: {case_id}")
            except Exception as e:
                actions.append(f"Case failed: {e}")
        return self._record("ioc_match_response", f"ioc={ioc.indicator}", src_ip, actions, True, case_id)

    def _run_honeypot_response(self, hit) -> PlaybookRun:
        actions = []; case_id = ""
        src_ip = hit.src_ip
        if self.firewall:
            try:
                self.firewall.block_ip(src_ip, f"SOAR honeypot hit ({hit.service})", "soar")
                actions.append(f"BLOCKED {src_ip} (honeypot)")
            except Exception as e:
                actions.append(f"Block failed: {e}")
        if self.ioc_mgr:
            try:
                if not self.ioc_mgr.match(src_ip):
                    self.ioc_mgr.add_ioc(src_ip,"ip","high",
                        f"Honeypot attacker ({hit.service})",["soar","honeypot"],"AHRAS-SOAR","soar")
                actions.append(f"IOC added: {src_ip}")
            except Exception as e:
                actions.append(f"IOC failed: {e}")
        if self.case_mgr:
            try:
                case = self.case_mgr.create_case(
                    title=f"[SOAR] Honeypot Hit: {src_ip} ({hit.service})",
                    description=f"Attacker interacted with {hit.service} honeypot.\nData: {hit.data[:200]}",
                    priority="HIGH", created_by="soar",
                    affected_ips=[src_ip], tags=["soar","honeypot",hit.service.lower()]
                )
                case_id = case.case_id
                self._graph_ingest_case(case, [src_ip])
                actions.append(f"CASE created: {case_id}")
            except Exception as e:
                actions.append(f"Case failed: {e}")
        return self._record("honeypot_response", f"service={hit.service}", src_ip, actions, True, case_id)

    def _run_correlation_response(self, incident: dict) -> PlaybookRun:
        actions = []; case_id = ""; src_ip = incident.get("src_ip","")
        if self.case_mgr:
            try:
                case = self.case_mgr.create_case(
                    title=f"[SOAR] Correlated Incident: {incident.get('rule_name','')}",
                    description=f"{incident.get('description','')}\n"
                                f"Events: {incident.get('event_count',0)}\n"
                                f"Confidence: {incident.get('confidence',0)*100:.0f}%",
                    priority="CRITICAL" if incident.get("severity")=="CRITICAL" else "HIGH",
                    created_by="soar", attack_type=", ".join(incident.get("attack_types",[])),
                    affected_ips=[src_ip], mitre_technique=incident.get("mitre_technique",""),
                    tags=["soar","correlation","auto"]
                )
                case_id = case.case_id
                self._graph_ingest_case(case, [src_ip])
                actions.append(f"CASE created: {case_id}")
            except Exception as e:
                actions.append(f"Case failed: {e}")
        if self.alert_mgr:
            try:
                self.alert_mgr._push_notification(
                    "SOAR", incident.get("incident_id",""),
                    f"🤖 SOAR: Correlated incident {incident.get('rule_name','')} — case {case_id}"
                )
                actions.append("NOTIFICATION sent")
            except Exception as e:
                actions.append(f"Notify failed: {e}")
        return self._record("correlation_response",
                            f"rule={incident.get('rule_id','')}", src_ip, actions, True, case_id)

    # ── Internal ───────────────────────────────────────────────────────────────

    def _record(self, playbook, trigger, src_ip, actions, success, case_id="") -> PlaybookRun:
        with self._lock:
            self._total += 1
            run = PlaybookRun(
                run_id=f"SOAR-{self._total:05d}", playbook=playbook,
                trigger=trigger, src_ip=src_ip, actions_taken=actions,
                success=success, case_id=case_id
            )
            self._runs.appendleft(run)
        logger.info(f"SOAR [{playbook}] {src_ip}: {actions}")
        return run

    def recent_runs(self, limit=50) -> List[dict]:
        with self._lock:
            return [r.to_dict() for r in list(self._runs)[:limit]]

    def stats(self) -> dict:
        with self._lock:
            by_pb: Dict[str,int] = {}
            for r in self._runs:
                by_pb[r.playbook] = by_pb.get(r.playbook,0)+1
            return {"total_runs":self._total,"recent":len(self._runs),"by_playbook":by_pb}
