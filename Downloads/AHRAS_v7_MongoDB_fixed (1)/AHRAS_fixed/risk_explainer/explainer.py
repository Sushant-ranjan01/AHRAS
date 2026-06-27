"""
AHRAS v4 — Risk Explainer  (Research Contribution Module)
══════════════════════════════════════════════════════════
Most SIEM/IDS systems show only a risk number.
AHRAS explains WHY the score is what it is — breaking it into
weighted sub-components so an analyst can justify and audit every decision.

Score Components (max contribution to the 0–100 scale):
  ┌──────────────────────┬─────────┬─────────────────────────────────────────┐
  │ Component            │ Max Pts │ Description                             │
  ├──────────────────────┼─────────┼─────────────────────────────────────────┤
  │ Threat Intelligence  │   30    │ Known-bad IP/domain/hash feeds          │
  │ Asset Criticality    │   20    │ How important is the targeted asset?    │
  │ MITRE Technique      │   20    │ Severity of mapped ATT&CK technique     │
  │ UBA / Behaviour      │   15    │ Deviation from baseline user behaviour  │
  │ ML Anomaly           │   15    │ Anomaly score from the ML engine        │
  └──────────────────────┴─────────┴─────────────────────────────────────────┘
  Total possible = 100 (before trust reduction, cap, and boosts)

The explainer re-derives each component from the raw RiskResult so the
explanation always matches the score shown to the analyst.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger("ahras.risk_explainer")

# ── Component weights (must sum to 100) ──────────────────────────────────────
WEIGHTS = {
    "threat_intel":    30,
    "asset":           20,
    "mitre":           20,
    "uba":             15,
    "ml_anomaly":      15,
}
assert sum(WEIGHTS.values()) == 100, "Component weights must sum to 100"

# MITRE technique → severity (0–1 scale)
_MITRE_SEVERITY: Dict[str, float] = {
    "T1486": 1.00,  # Ransomware
    "T1041": 0.85,  # Exfiltration
    "T1021": 0.80,  # Remote Services
    "T1190": 0.80,  # Exploit Public App
    "T1095": 0.75,  # Non-Application Layer Protocol
    "T1071": 0.65,  # App Layer Protocol C2
    "T1548": 0.65,  # Elevation Control
    "T1543": 0.65,  # Create/Modify System Process
    "T1053": 0.60,  # Scheduled Task
    "T1110": 0.55,  # Brute Force
    "T1136": 0.55,  # Create Account
    "T1059": 0.50,  # Command & Scripting
    "T1078": 0.45,  # Valid Accounts
    "T1498": 0.40,  # DDoS
    "T1595": 0.30,  # Active Scanning
    "T1046": 0.25,  # Network Service Discovery
    "T1083": 0.20,  # File Discovery
}

# Human-readable MITRE names
_MITRE_NAMES: Dict[str, str] = {
    "T1486": "Data Encrypted for Impact (Ransomware)",
    "T1041": "Exfiltration Over C2 Channel",
    "T1021": "Remote Services",
    "T1190": "Exploit Public-Facing Application",
    "T1095": "Non-Standard Protocol",
    "T1071": "Application Layer Protocol (C2)",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1543": "Create or Modify System Process",
    "T1053": "Scheduled Task / Job",
    "T1110": "Brute Force",
    "T1136": "Create Account",
    "T1059": "Command & Scripting Interpreter",
    "T1078": "Valid Accounts",
    "T1498": "Network Denial of Service",
    "T1595": "Active Scanning",
    "T1046": "Network Service Discovery",
    "T1083": "File and Directory Discovery",
}


@dataclass
class ComponentScore:
    """Score for a single risk component."""
    name: str           # component key
    label: str          # human-readable label
    raw_value: float    # 0.0–1.0 normalised input
    weight: int         # max points this component can contribute
    contribution: float # actual points contributed (raw_value * weight)
    reason: str         # one-line explanation
    detail: str = ""    # optional longer detail

    def to_dict(self) -> dict:
        return {
            "name":         self.name,
            "label":        self.label,
            "raw_value":    round(self.raw_value, 3),
            "weight":       self.weight,
            "contribution": round(self.contribution, 1),
            "percentage":   round((self.contribution / self.weight * 100) if self.weight else 0, 1),
            "reason":       self.reason,
            "detail":       self.detail,
        }


@dataclass
class RiskExplanation:
    """Full explanation of a risk score."""
    src_ip: str
    final_score: float          # 0–100
    severity: str
    components: List[ComponentScore] = field(default_factory=list)
    adjustments: List[Dict] = field(default_factory=list)   # trust reductions, boosts, caps
    verdict: str = ""           # one-sentence analyst-ready summary
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "src_ip":          self.src_ip,
            "final_score":     round(self.final_score, 1),
            "severity":        self.severity,
            "components":      [c.to_dict() for c in self.components],
            "component_total": round(sum(c.contribution for c in self.components), 1),
            "adjustments":     self.adjustments,
            "verdict":         self.verdict,
            "recommendations": self.recommendations,
        }


class RiskExplainer:
    """
    Takes a RiskResult (from RiskEngine) and produces a human-readable
    RiskExplanation that breaks the score into labelled sub-components.

    This is the research contribution: most systems show a number.
    AHRAS shows WHY.
    """

    def __init__(self):
        logger.info("RiskExplainer ready")

    def explain(self, risk_result: Any, uba_score: float = 0.0,
                threat_intel_score: float = 0.0,
                asset_criticality: float = 0.0) -> RiskExplanation:
        """
        Build a full explanation from a RiskResult object.

        Parameters
        ----------
        risk_result         : RiskResult from RiskEngine.evaluate()
        uba_score           : 0.0–1.0 from UBAEngine (inject externally)
        threat_intel_score  : 0.0–1.0 from ThreatIntelManager (inject externally)
        asset_criticality   : 0.0–1.0  (asset criticality / 10)
        """
        r = risk_result
        components: List[ComponentScore] = []
        adjustments: List[Dict] = []

        # ── 1. Threat Intelligence component ─────────────────────────────
        ti_raw = max(0.0, min(1.0, float(threat_intel_score)))
        # Fallback: infer from trust score (inverse — unknown/bad = higher)
        if ti_raw == 0.0:
            trust = getattr(r, "trust_score", 0.1)
            ti_raw = max(0.0, 1.0 - float(trust))
        ti_contrib = ti_raw * WEIGHTS["threat_intel"]
        ti_reason = (
            "Known malicious indicator in threat intel feeds" if ti_raw > 0.7
            else "Partially matched threat intel (low confidence)" if ti_raw > 0.3
            else "No significant threat intel match"
        )
        components.append(ComponentScore(
            name="threat_intel", label="Threat Intelligence",
            raw_value=ti_raw, weight=WEIGHTS["threat_intel"],
            contribution=ti_contrib, reason=ti_reason,
            detail=f"Trust factor: {getattr(r, 'trust_score', 0.1):.2f} | "
                   f"Resolved domain: {getattr(r, 'domain', 'unknown')}",
        ))

        # ── 2. Asset Criticality component ────────────────────────────────
        ac_raw = max(0.0, min(1.0, float(asset_criticality)))
        # Fallback: use asset_boost from risk engine (0–20 pts → 0–1 scale)
        if ac_raw == 0.0:
            ab = getattr(r, "asset_boost", 0.0)
            ac_raw = max(0.0, min(1.0, float(ab) / 20.0))
        ac_contrib = ac_raw * WEIGHTS["asset"]
        ac_reason = (
            "Critical asset targeted — maximum exposure" if ac_raw >= 0.8
            else "High-value asset in scope" if ac_raw >= 0.5
            else "Standard asset — moderate criticality" if ac_raw >= 0.2
            else "Low-criticality or unregistered asset"
        )
        components.append(ComponentScore(
            name="asset", label="Asset Criticality",
            raw_value=ac_raw, weight=WEIGHTS["asset"],
            contribution=ac_contrib, reason=ac_reason,
            detail=f"Asset boost applied by risk engine: {getattr(r, 'asset_boost', 0.0):.1f} pts",
        ))

        # ── 3. MITRE Technique component ──────────────────────────────────
        mitre_id = getattr(r, "mitre_boost", None)
        # Try to get the technique ID from the result object
        # (mitre_boost is points, we need the ID — look in various places)
        mitre_technique_id = ""
        if hasattr(r, "mitre_technique"):
            mitre_technique_id = r.mitre_technique
        mitre_sev = _MITRE_SEVERITY.get(mitre_technique_id, 0.0)
        # Fallback: reverse-engineer from mitre_boost points
        if mitre_sev == 0.0:
            mb = float(getattr(r, "mitre_boost", 0.0))
            mitre_sev = min(1.0, mb / 25.0)   # max boost is 25 pts
        mitre_contrib = mitre_sev * WEIGHTS["mitre"]
        mitre_name = _MITRE_NAMES.get(mitre_technique_id, "Unknown / not mapped")
        mitre_reason = (
            f"Mapped to {mitre_technique_id}: {mitre_name}" if mitre_technique_id
            else "No MITRE technique mapped for this event"
        )
        components.append(ComponentScore(
            name="mitre", label="MITRE ATT&CK Technique",
            raw_value=mitre_sev, weight=WEIGHTS["mitre"],
            contribution=mitre_contrib, reason=mitre_reason,
            detail=f"Technique severity: {mitre_sev:.0%} of maximum",
        ))

        # ── 4. UBA / Behavioural component ────────────────────────────────
        uba_raw = max(0.0, min(1.0, float(uba_score)))
        # Fallback: derive from behavioral_drift
        if uba_raw == 0.0:
            drift = float(getattr(r, "behavioral_drift", 0.0))
            uba_raw = min(1.0, drift / 500.0)
        uba_contrib = uba_raw * WEIGHTS["uba"]
        uba_reason = (
            "Significant behavioural deviation — unusual activity pattern" if uba_raw > 0.6
            else "Moderate behavioural drift detected" if uba_raw > 0.3
            else "Behaviour within normal baseline range"
        )
        components.append(ComponentScore(
            name="uba", label="User / Entity Behaviour (UBA)",
            raw_value=uba_raw, weight=WEIGHTS["uba"],
            contribution=uba_contrib, reason=uba_reason,
            detail=f"Behavioural drift metric: {getattr(r, 'behavioral_drift', 0.0):.1f}",
        ))

        # ── 5. ML Anomaly component ────────────────────────────────────────
        anom_raw = float(getattr(r, "anomaly_score", 0.0))   # 0.0 or 1.0 from current engine
        # Also factor in signature score
        sig_factor = min(1.0, float(getattr(r, "signature_score", 0.0)) / 100.0)
        ml_raw = max(anom_raw, sig_factor * 0.5)   # blend anomaly flag with signature confidence
        ml_raw = max(0.0, min(1.0, ml_raw))
        ml_contrib = ml_raw * WEIGHTS["ml_anomaly"]
        ml_reason = (
            "ML anomaly flag raised AND strong signature match" if anom_raw > 0 and sig_factor > 0.5
            else "ML anomaly detected" if anom_raw > 0
            else "Signature engine confidence elevated" if sig_factor > 0.5
            else "No ML anomaly or signature hit"
        )
        components.append(ComponentScore(
            name="ml_anomaly", label="ML Anomaly Detection",
            raw_value=ml_raw, weight=WEIGHTS["ml_anomaly"],
            contribution=ml_contrib, reason=ml_reason,
            detail=f"Anomaly flag: {bool(anom_raw)} | Signature confidence: {sig_factor:.0%}",
        ))

        # ── Compute raw component total ────────────────────────────────────
        component_total = sum(c.contribution for c in components)

        # ── Adjustments ───────────────────────────────────────────────────
        final = component_total
        trust = float(getattr(r, "trust_score", 0.1))
        signal = int(getattr(r, "signal_strength", 0))

        if trust > 0.7 and signal < 3:
            reduction = final * 0.5
            final -= reduction
            adjustments.append({
                "type":    "trust_reduction",
                "label":   "Trusted domain reduction",
                "value":   -round(reduction, 1),
                "reason":  f"Source resolves to trusted domain (trust={trust:.2f}) with low signal strength ({signal})",
            })

        if signal >= 4:
            boost = final * 0.5
            final += boost
            adjustments.append({
                "type":   "multi_signal_boost",
                "label":  "Multi-signal amplification",
                "value":  +round(boost, 1),
                "reason": f"{signal}/5 signals fired — high confidence composite threat",
            })
        elif signal >= 3:
            boost = final * 0.2
            final += boost
            adjustments.append({
                "type":   "multi_signal_boost",
                "label":  "Multi-signal boost (moderate)",
                "value":  +round(boost, 1),
                "reason": f"{signal}/5 signals fired",
            })

        # Cap at 100
        if final > 100:
            cap_reduction = final - 100
            adjustments.append({
                "type":   "cap",
                "label":  "Score capped at maximum",
                "value":  -round(cap_reduction, 1),
                "reason": "Final score cannot exceed 100",
            })
            final = 100.0

        final = max(0.0, final)
        severity = getattr(r, "severity", _score_to_severity(final))

        # ── Verdict ───────────────────────────────────────────────────────
        verdict = _build_verdict(
            src_ip=getattr(r, "src_ip", "unknown"),
            final=final, severity=severity,
            top_component=max(components, key=lambda c: c.contribution),
            mitre_id=mitre_technique_id, mitre_name=mitre_name,
        )

        # ── Recommendations ───────────────────────────────────────────────
        recommendations = _build_recommendations(final, severity, components, mitre_technique_id)

        return RiskExplanation(
            src_ip=getattr(r, "src_ip", "unknown"),
            final_score=round(final, 1),
            severity=severity,
            components=components,
            adjustments=adjustments,
            verdict=verdict,
            recommendations=recommendations,
        )

    def explain_dict(self, risk_result: Any, **kwargs) -> dict:
        """Convenience — returns a plain dict instead of RiskExplanation."""
        return self.explain(risk_result, **kwargs).to_dict()


# ── Helper functions ─────────────────────────────────────────────────────────

def _score_to_severity(score: float) -> str:
    if score >= 85:  return "CRITICAL"
    if score >= 50:  return "HIGH"
    if score >= 20:  return "MEDIUM"
    return "LOW"


def _build_verdict(src_ip: str, final: float, severity: str,
                   top_component: ComponentScore,
                   mitre_id: str, mitre_name: str) -> str:
    if final >= 85:
        base = f"CRITICAL threat from {src_ip}"
    elif final >= 50:
        base = f"HIGH-risk activity from {src_ip}"
    elif final >= 20:
        base = f"Moderate-risk event from {src_ip}"
    else:
        base = f"Low-risk event from {src_ip}"

    top_label = top_component.label
    top_pct   = int(top_component.contribution / top_component.weight * 100) if top_component.weight else 0

    verdict = f"{base}. Primary driver: {top_label} ({top_component.contribution:.1f} pts, {top_pct}% of max)."
    if mitre_id:
        verdict += f" Technique: {mitre_id} — {mitre_name}."
    return verdict


def _build_recommendations(final: float, severity: str,
                            components: List[ComponentScore],
                            mitre_id: str) -> List[str]:
    recs: List[str] = []

    if final >= 85:
        recs.append("Immediately isolate the source IP from the network.")
        recs.append("Open a high-priority incident case and assign a senior analyst.")
    elif final >= 50:
        recs.append("Escalate to Tier 2 analyst for investigation.")
        recs.append("Apply temporary rate-limiting or monitoring rule for this IP.")
    elif final >= 20:
        recs.append("Flag for follow-up review within 24 hours.")
    else:
        recs.append("Log and monitor — no immediate action required.")

    # Component-specific recommendations
    for c in components:
        if c.name == "threat_intel" and c.raw_value > 0.5:
            recs.append("Cross-reference with external threat intel platforms (VirusTotal, Shodan, AbuseIPDB).")
        if c.name == "asset" and c.raw_value > 0.7:
            recs.append("Notify the asset owner and verify no unauthorised access occurred.")
        if c.name == "uba" and c.raw_value > 0.5:
            recs.append("Review user account for signs of compromise or insider threat.")
        if c.name == "ml_anomaly" and c.raw_value > 0.5:
            recs.append("Retrain anomaly baseline if this is a known-good change in behaviour.")

    if mitre_id == "T1486":
        recs.append("Initiate ransomware response playbook immediately.")
    elif mitre_id == "T1041":
        recs.append("Check egress firewall rules and network flows for data exfiltration.")
    elif mitre_id == "T1110":
        recs.append("Enforce account lockout policy and review authentication logs.")

    return recs
