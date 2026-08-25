"""
AHRAS v4 — Deception-Driven Rule Generator
(Phase 2 — Research Contribution, closes the loop: honeypot -> rule -> firewall)
═══════════════════════════════════════════════════════════════════════════
Problem: honeypot/honeypot.py records hits but they just sit there as log
entries — nothing automatically turns "an attacker just tried this exact
technique against our decoy" into a rule that protects the *real*
infrastructure.

Solution: every honeypot hit is guaranteed malicious (by construction —
there are no legitimate users of a honeypot), so we can safely and
immediately:
  1. extract simple TTP indicators from the payload the attacker sent
     (download-and-execute commands, SQLi/command-injection patterns,
     credential strings, known scanner user-agents, etc),
  2. synthesize a Sigma rule from those indicators and load it straight
     into detection/sigma_engine so future traffic matching the same
     pattern gets flagged everywhere, not just on the honeypot, and
  3. push the attacker's source IP to the firewall's block list.

This is intentionally pattern-based (regex over the captured payload), not
another ML model — the honeypot data volume per unique attacker is far too
small to train anything reliable on, and pattern extraction is fast enough
to run inline on every hit with no added latency.
"""
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("ahras.honeypot.deception_feedback")

# (label, regex, mitre tag) — checked in order, first few matches kept per hit
_TTP_PATTERNS = [
    ("download_execute", re.compile(r"(wget|curl)\s+\S+.*(\||;)\s*(sh|bash)", re.I), "attack.t1105"),
    ("download_execute", re.compile(r"certutil\s+-urlcache", re.I), "attack.t1105"),
    ("powershell_encoded", re.compile(r"powershell.*-enc(odedcommand)?\s+\S+", re.I), "attack.t1059.001"),
    ("sql_injection", re.compile(r"(\bunion\b.*\bselect\b|'\s*or\s*'1'\s*=\s*'1)", re.I), "attack.t1190"),
    ("command_injection", re.compile(r"[;&|`]\s*(cat|ls|whoami|id|uname)\b", re.I), "attack.t1059"),
    ("credential_probe", re.compile(r"(root:|admin:|password\s*=)", re.I), "attack.t1110"),
    ("path_traversal", re.compile(r"\.\./\.\./"), "attack.t1083"),
]


@dataclass
class GeneratedRuleResult:
    ttp_id: str
    label: str
    mitre_tag: str
    src_ip: str
    sigma_rule_id: str
    firewall_blocked: bool
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "ttp_id": self.ttp_id, "label": self.label, "mitre_tag": self.mitre_tag,
            "src_ip": self.src_ip, "sigma_rule_id": self.sigma_rule_id,
            "firewall_blocked": self.firewall_blocked,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)),
        }


class DeceptionRuleGenerator:
    """
    Wire this up once at startup:
        gen = DeceptionRuleGenerator(sigma_engine=..., firewall=..., ioc_mgr=...)
        honeypot.on_hit_callbacks.append(gen.handle_hit)
    """

    def __init__(self, sigma_engine=None, firewall=None, ioc_mgr=None):
        self.sigma_engine = sigma_engine
        self.firewall = firewall
        self.ioc_mgr = ioc_mgr
        self._seen_ips: set = set()

    def _extract_ttps(self, payload: str) -> List[tuple]:
        hits = []
        for label, pattern, mitre_tag in _TTP_PATTERNS:
            if pattern.search(payload or ""):
                hits.append((label, mitre_tag, pattern.pattern))
        return hits

    def _synthesize_sigma_rule(self, label: str, mitre_tag: str, pattern_src: str, src_ip: str) -> Optional[str]:
        if self.sigma_engine is None:
            return None
        rule_id = f"auto_deception_{label}_{uuid.uuid4().hex[:8]}"
        rule_dict = {
            "id": rule_id,
            "title": f"Auto-generated: {label.replace('_', ' ').title()} (observed via honeypot from {src_ip})",
            "level": "high",
            "tags": [mitre_tag, "source.honeypot_auto"],
            "detection": {
                "selection": {"payload|contains": [pattern_src]},
                "condition": "selection",
            },
        }
        try:
            self.sigma_engine.add_rule_dict(rule_dict)
            return rule_id
        except Exception as exc:
            logger.error("Failed to add auto-generated Sigma rule: %s", exc)
            return None

    def handle_hit(self, hit) -> List[GeneratedRuleResult]:
        """
        hit: a honeypot.honeypot.HoneypotHit (or any object/dict with
        .data/['data'] and .src_ip/['src_ip']).
        """
        payload = hit.data if hasattr(hit, "data") else hit.get("data", "")
        src_ip = hit.src_ip if hasattr(hit, "src_ip") else hit.get("src_ip", "unknown")

        ttps = self._extract_ttps(payload)
        results: List[GeneratedRuleResult] = []

        # Always worth blocking on a raw honeypot hit even with no TTP match —
        # any interaction with a decoy service is inherently malicious.
        blocked = False
        if self.firewall is not None and src_ip not in self._seen_ips:
            resp = self.firewall.block_ip(src_ip, reason="Automated: honeypot interaction", operator="deception_feedback")
            blocked = bool(resp.get("success"))
            self._seen_ips.add(src_ip)

        if self.ioc_mgr is not None:
            try:
                self.ioc_mgr.add_ioc(
                    indicator=src_ip, ioc_type="ip", threat_level="high",
                    description="Auto-added from honeypot interaction TTP extraction",
                    tags=["honeypot", "auto_generated"],
                    source="honeypot_deception_feedback",
                    added_by="deception_feedback",
                )
            except Exception:
                pass

        if not ttps:
            results.append(GeneratedRuleResult(
                ttp_id="generic_honeypot_hit", label="honeypot_interaction",
                mitre_tag="attack.t1595", src_ip=src_ip,
                sigma_rule_id="", firewall_blocked=blocked,
            ))
            return results

        for label, mitre_tag, pattern_src in ttps:
            rule_id = self._synthesize_sigma_rule(label, mitre_tag, pattern_src, src_ip)
            results.append(GeneratedRuleResult(
                ttp_id=f"{label}:{uuid.uuid4().hex[:6]}", label=label, mitre_tag=mitre_tag,
                src_ip=src_ip, sigma_rule_id=rule_id or "", firewall_blocked=blocked,
            ))
            logger.warning("Deception feedback: %s from %s -> Sigma rule %s, firewall_blocked=%s",
                            label, src_ip, rule_id, blocked)
        return results


deception_rule_generator = DeceptionRuleGenerator()
