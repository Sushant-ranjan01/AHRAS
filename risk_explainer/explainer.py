"""
AHRAS v5 — Risk Explainer  (Research Contribution Module)
══════════════════════════════════════════════════════════
Most SIEM/IDS systems show only a risk number.
AHRAS explains WHY the score is what it is — breaking it into
labelled sub-components so an analyst can justify and audit every decision.

── Fix (v5): faithful-by-construction reconstruction ────────────────────────
The v4 explainer scored components against an INDEPENDENT weight table
(threat_intel=30, asset=20, mitre=20, uba=15, ml_anomaly=15) that had no
relationship to risk_engine.risk_scorer's actual formula. That table could
disagree with the real score -- the explanation for a CRITICAL event could
show component contributions that summed to a MEDIUM number, or vice versa,
because it was quietly re-deriving a different, decorative score rather than
explaining the real one.

This version explains ONLY what RiskEngine.evaluate() actually computed. It
reads risk_result.raw_components -- which RiskEngine records verbatim at
every step of the formula (base signals -> strength multiplier -> rule
boosts -> trust adjustment -> MITRE/asset/history boosts -> cap) -- and
turns those exact numbers into labelled components + adjustments. Summing
every component and adjustment reproduces risk_result.risk_score_100 by
construction, not by coincidence.

UBA score / threat-intel score / externally-supplied asset criticality are
NOT part of RiskEngine's formula (see risk_engine.risk_scorer's module
docstring for why -- different entity stream, or circular-dependency risk).
They are surfaced here as `contextual_signals`: informative for the analyst,
clearly separated from -- and never summed into -- the score breakdown.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger("ahras.risk_explainer")

# -- Base-signal weights, mirrored from RiskEngine's defaults ----------------
# (only used as a fallback / documentation reference -- the live weights_used
# actually stored in raw_components always take precedence, so this stays
# correct even when the adaptive learner has changed the live weights.)
DEFAULT_BASE_WEIGHTS = {
    "signature":  0.40,
    "anomaly":    0.30,
    "density":    0.20,
    "drift_rate": 0.10,
}
# Points on the 0-100 scale each base signal can contribute at full weight
# (informational only -- used by the /api/risk/weights endpoint).
WEIGHTS = {
    "signature":  int(DEFAULT_BASE_WEIGHTS["signature"] * 100),
    "anomaly":    int(DEFAULT_BASE_WEIGHTS["anomaly"] * 100),
    "density":    int(DEFAULT_BASE_WEIGHTS["density"] * 100),
    "drift_rate": int(DEFAULT_BASE_WEIGHTS["drift_rate"] * 100),
}
assert sum(WEIGHTS.values()) == 100, "Base signal weights must sum to 100"

# Boosts on top of the base 0-100 signal fusion -- these can push the
# pre-cap score above 100 before RiskEngine clamps it. Documented here so
# analysts/the /api/risk/weights endpoint understand the full picture, not
# just the base-signal portion.
MAX_ADDITIONAL_BOOSTS = {
    "strength_multiplier": "x1.0 - x1.5 on the base score (3+/5 or 4+/5 signals firing)",
    "rule_boosts":          "up to +170 pts (unique_ports, syn_count, rate, pps rules; see risk_scorer.py)",
    "mitre_boost":          "up to +25 pts (ransomware/exfil/etc. technique severity)",
    "asset_boost":          "up to +20 pts (targeted asset criticality)",
    "history_boost":        "up to +45 pts (recidivism -- repeat-offender indicator)",
    "trust_discount":       "x0.4 - x0.5 reduction, or short-circuit to 0, for trusted/local low-signal traffic",
}

# MITRE technique -> human name (used only when a mitre_id is explicitly
# passed to explain(); RiskResult itself doesn't retain the technique id,
# only the point value it contributed).
_MITRE_NAMES: Dict[str, str] = {
    "T1486": "Data Encrypted for Impact (Ransomware)",
    "T1041": "Exfiltration Over C2 Channel",
    "T1021": "Remote Services",
    "T1190": "Exploit Public-Facing Application",
    "T1095": "Non-Standard Protocol",
    "T1071": "Application Layer Protocol (C2)",
    "T1110": "Brute Force",
    "T1498": "Network Denial of Service",
    "T1046": "Network Service Discovery",
}

_TRUST_LABELS = {
    "trusted_local_ignored":  "Trusted local traffic -- suppressed to zero",
    "trusted_local_discount": "Trusted/private-network discount (x0.4)",
    "trusted_domain_discount": "Trusted-domain discount (x0.5)",
    "none": "No trust adjustment",
}


@dataclass
class ComponentScore:
    """Score for a single base-signal component (part of the weighted fusion)."""
    name: str           # component key
    label: str          # human-readable label
    raw_value: float    # 0.0-1.0 normalised input
    weight: float        # max points this component can contribute
    contribution: float # actual points contributed (raw_value * weight)
    reason: str         # one-line explanation
    detail: str = ""    # optional longer detail

    def to_dict(self) -> dict:
        return {
            "name":         self.name,
            "label":        self.label,
            "raw_value":    round(self.raw_value, 3),
            "weight":       round(self.weight, 1),
            "contribution": round(self.contribution, 1),
            "percentage":   round((self.contribution / self.weight * 100) if self.weight else 0, 1),
            "reason":       self.reason,
            "detail":       self.detail,
        }


@dataclass
class RiskExplanation:
    """Full explanation of a risk score."""
    src_ip: str
    final_score: float          # 0-100 -- exactly risk_result.risk_score_100
    severity: str
    components: List[ComponentScore] = field(default_factory=list)
    adjustments: List[Dict] = field(default_factory=list)   # multiplier/boosts/trust/cap, in applied order
    contextual_signals: List[Dict] = field(default_factory=list)  # NOT part of the score -- for analyst context only
    verdict: str = ""           # one-sentence analyst-ready summary
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "src_ip":            self.src_ip,
            "final_score":       round(self.final_score, 1),
            "severity":          self.severity,
            "components":        [c.to_dict() for c in self.components],
            "component_total":   round(sum(c.contribution for c in self.components), 1),
            "adjustments":       self.adjustments,
            "contextual_signals": self.contextual_signals,
            "verdict":           self.verdict,
            "recommendations":   self.recommendations,
        }


class RiskExplainer:
    """
    Takes a RiskResult (from RiskEngine) and produces a human-readable
    RiskExplanation that breaks the score into labelled sub-components,
    reconstructed EXACTLY from the same raw_components RiskEngine recorded
    while computing the score -- see module docstring.
    """

    def __init__(self):
        logger.info("RiskExplainer ready (faithful-reconstruction mode)")

    def explain(self, risk_result: Any, uba_score: float = 0.0,
                threat_intel_score: float = 0.0,
                asset_criticality: float = 0.0,
                mitre_id: str = "") -> RiskExplanation:
        """
        Build a full explanation from a RiskResult object.

        Parameters
        ----------
        risk_result          : RiskResult from RiskEngine.evaluate()
        uba_score             : 0.0-1.0 from UBAEngine -- CONTEXTUAL ONLY, not
                               part of RiskEngine's formula (different event
                               stream; see risk_scorer.py's module docstring).
        threat_intel_score    : 0.0-1.0 from ThreatIntelManager -- CONTEXTUAL ONLY.
        asset_criticality     : 0.0-1.0 externally-supplied asset criticality,
                               shown for reference -- the score itself already
                               includes RiskEngine's OWN asset_boost (from its
                               injected asset manager) if one fired.
        mitre_id               : optional MITRE technique id, purely for a
                               human-readable label -- RiskResult only retains
                               the point value it contributed (mitre_boost),
                               not the id, so this must be passed in if wanted.
        """
        r = risk_result
        rc: Dict[str, Any] = dict(getattr(r, "raw_components", None) or {})

        components: List[ComponentScore] = []
        adjustments: List[Dict] = []

        # -- Base weighted-fusion components (exactly S, A, T, drift+rate) ---
        weights_used = rc.get("weights_used", DEFAULT_BASE_WEIGHTS)
        alpha = float(weights_used.get("signature",  DEFAULT_BASE_WEIGHTS["signature"]))
        beta  = float(weights_used.get("anomaly",    DEFAULT_BASE_WEIGHTS["anomaly"]))
        gamma = float(weights_used.get("density",    DEFAULT_BASE_WEIGHTS["density"]))
        delta = float(weights_used.get("drift_rate", DEFAULT_BASE_WEIGHTS["drift_rate"]))

        S  = float(rc.get("signature", min(float(getattr(r, "signature_score", 0.0)) / 100.0, 1.0)))
        A  = float(rc.get("anomaly", float(getattr(r, "anomaly_score", 0.0))))
        T  = float(rc.get("density", min(float(getattr(r, "temporal_density", 0.0)) / 50.0, 1.0)))
        BR = float(rc.get("drift_rate", 0.0))  # 0.0 - 2.0 (drift term + rate term, each capped at 1.0)

        components.append(ComponentScore(
            name="signature", label="Attack Signature Match",
            raw_value=S, weight=alpha * 100,
            contribution=S * alpha * 100,
            reason=("Strong signature match" if S > 0.7 else
                    "Moderate signature match" if S > 0.2 else
                    "No signature match -- Normal/low-confidence traffic"),
            detail=f"signature_score={getattr(r, 'signature_score', 0.0):.1f}/100, weight alpha={alpha:.2f}",
        ))
        components.append(ComponentScore(
            name="anomaly", label="ML Anomaly Flag",
            raw_value=A, weight=beta * 100,
            contribution=A * beta * 100,
            reason="ML anomaly flag raised" if A > 0 else "No ML anomaly flag",
            detail=f"weight beta={beta:.2f}",
        ))
        components.append(ComponentScore(
            name="density", label="Temporal Attack Density",
            raw_value=T, weight=gamma * 100,
            contribution=T * gamma * 100,
            reason=("High density of attack events for this source in the last 60s" if T > 0.5 else
                    "Some repeated attack events for this source" if T > 0.1 else
                    "No repeated attack density"),
            detail=f"temporal_density={getattr(r, 'temporal_density', 0.0):.1f} events/60s, weight gamma={gamma:.2f}",
        ))
        drift_raw01 = max(0.0, min(1.0, BR / 2.0))
        components.append(ComponentScore(
            name="drift_rate", label="Behavioural Drift + Packet Rate",
            raw_value=drift_raw01, weight=delta * 200,
            contribution=drift_raw01 * delta * 200,
            reason=("Significant deviation from this source's normal packet-count baseline, and/or a high packet rate"
                    if BR > 1.0 else
                    "Some drift from baseline or elevated packet rate" if BR > 0.2 else
                    "Behaviour within normal baseline, packet rate unremarkable"),
            detail=(f"behavioral_drift={getattr(r, 'behavioral_drift', 0.0):.1f}, "
                    f"packet_rate={getattr(r, 'packet_rate', 0.0):.1f}/30s, weight delta={delta:.2f}"),
        ))

        base_risk = float(rc.get("base_risk", sum(c.contribution for c in components)))

        # -- Adjustments, reconstructed in the exact order RiskEngine applies them --
        strength = int(rc.get("strength", getattr(r, "signal_strength", 0)))
        strength_mult = float(rc.get("strength_multiplier", 1.0))
        risk_after_strength = float(rc.get("risk_after_strength", base_risk * strength_mult))
        mult_delta = risk_after_strength - base_risk
        if abs(mult_delta) > 1e-9:
            adjustments.append({
                "type": "multi_signal_multiplier",
                "label": f"Multi-signal strength multiplier (x{strength_mult:.2f})",
                "value": round(mult_delta, 1),
                "reason": f"{strength}/5 independent signals fired for this event",
            })

        rule_boosts = rc.get("rule_boosts", [])
        for rb in rule_boosts:
            adjustments.append({
                "type": "rule_boost",
                "label": _humanize_rule(rb.get("rule", "")),
                "value": round(float(rb.get("points", 0.0)), 1),
                "reason": f"Behavioural rule '{rb.get('rule','')}' triggered",
            })
        risk_after_rules = float(rc.get("risk_after_rules", risk_after_strength + sum(
            float(rb.get("points", 0.0)) for rb in rule_boosts)))

        trust_adj = rc.get("trust_adjustment", {"type": "none", "factor": 1.0})
        risk_after_trust = float(rc.get("risk_after_trust", risk_after_rules))
        trust_delta = risk_after_trust - risk_after_rules
        trust_type = trust_adj.get("type", "none")
        if trust_type != "none" or abs(trust_delta) > 1e-9:
            adjustments.append({
                "type": "trust_adjustment",
                "label": _TRUST_LABELS.get(trust_type, trust_type),
                "value": round(trust_delta, 1),
                "reason": f"trust_score={getattr(r, 'trust_score', 0.1):.2f} (domain: {getattr(r, 'domain', 'unknown')}), signal_strength={strength}",
            })

        mb = float(rc.get("mitre_boost", getattr(r, "mitre_boost", 0.0)))
        if mb > 0:
            mname = _MITRE_NAMES.get(mitre_id, "")
            adjustments.append({
                "type": "mitre_boost",
                "label": "MITRE ATT&CK technique severity boost",
                "value": round(mb, 1),
                "reason": (f"Mapped technique {mitre_id} -- {mname}" if mitre_id and mname
                           else f"Mapped technique {mitre_id}" if mitre_id
                           else "Detected activity mapped to a scored MITRE ATT&CK technique"),
            })

        ab = float(rc.get("asset_boost", getattr(r, "asset_boost", 0.0)))
        if ab > 0:
            adjustments.append({
                "type": "asset_boost",
                "label": "Targeted-asset criticality boost",
                "value": round(ab, 1),
                "reason": "The destination asset is registered as business-critical",
            })

        hb = float(rc.get("history_boost", getattr(r, "history_boost", 0.0)))
        if hb > 0:
            adjustments.append({
                "type": "history_boost",
                "label": "Historical recidivism boost",
                "value": round(hb, 1),
                "reason": "This source has a history of prior incidents/alerts (see Historical Risk Engine)",
            })

        pre_cap_risk = float(rc.get("pre_cap_risk", risk_after_trust + mb + ab + hb))
        capped = bool(rc.get("capped", pre_cap_risk > 100.0 or pre_cap_risk < 0.0))
        if capped and pre_cap_risk > 100.0:
            adjustments.append({
                "type": "cap", "label": "Score capped at maximum",
                "value": round(100.0 - pre_cap_risk, 1),
                "reason": "Final score cannot exceed 100",
            })
        elif capped and pre_cap_risk < 0.0:
            adjustments.append({
                "type": "floor", "label": "Score floored at minimum",
                "value": round(0.0 - pre_cap_risk, 1),
                "reason": "Final score cannot go below 0",
            })

        # Ground truth: use RiskEngine's own final number rather than
        # re-summing floats, so this can never drift from the real score
        # due to rounding in the stored raw_components.
        final = round(float(getattr(r, "risk_score_100", max(0.0, min(100.0, pre_cap_risk)))), 1)
        severity = getattr(r, "severity", _score_to_severity(final))

        # -- Contextual signals -- NOT part of the score --------------------
        contextual_signals: List[Dict] = []
        if uba_score:
            contextual_signals.append({
                "name": "uba", "label": "User/Entity Behaviour Analytics",
                "value": round(max(0.0, min(1.0, float(uba_score))), 3),
                "note": "Tracked on a separate (username) event stream -- informational only, not summed into the score.",
            })
        if threat_intel_score:
            contextual_signals.append({
                "name": "threat_intel", "label": "External Threat Intelligence",
                "value": round(max(0.0, min(1.0, float(threat_intel_score))), 3),
                "note": "Not summed into the score -- cross-reference manually or via /api/threat-intel.",
            })
        if asset_criticality:
            contextual_signals.append({
                "name": "asset_criticality_supplied", "label": "Externally-supplied asset criticality",
                "value": round(max(0.0, min(1.0, float(asset_criticality))), 3),
                "note": ("For reference only. RiskEngine's own asset_boost above already reflects its "
                         "injected asset manager's criticality lookup, if one fired."),
            })

        # -- Verdict ----------------------------------------------------------
        candidates = list(components) + [
            _AdjAsComponent(a) for a in adjustments if a["type"] not in ("cap", "floor")
        ]
        top_item = max(candidates, key=lambda x: x.contribution, default=None)
        verdict = _build_verdict(
            src_ip=getattr(r, "src_ip", "unknown"),
            final=final, severity=severity, top_item=top_item,
            mitre_id=mitre_id, mitre_name=_MITRE_NAMES.get(mitre_id, ""),
        )

        # -- Recommendations --------------------------------------------------
        recommendations = _build_recommendations(
            final, severity, adjustments, contextual_signals, mitre_id, trust_type,
        )

        return RiskExplanation(
            src_ip=getattr(r, "src_ip", "unknown"),
            final_score=final,
            severity=severity,
            components=components,
            adjustments=adjustments,
            contextual_signals=contextual_signals,
            verdict=verdict,
            recommendations=recommendations,
        )

    def explain_dict(self, risk_result: Any, **kwargs) -> dict:
        """Convenience -- returns a plain dict instead of RiskExplanation."""
        return self.explain(risk_result, **kwargs).to_dict()


# -- Helper functions ----------------------------------------------------------

class _AdjAsComponent:
    """Thin wrapper so adjustments (dicts) and components (dataclasses) can be
    ranked together for 'top driver' selection in the verdict."""
    def __init__(self, adj: dict):
        self._adj = adj
        self.label = adj["label"]
        self.contribution = abs(adj["value"])

    def __getitem__(self, k):
        return self._adj[k]


def _humanize_rule(rule: str) -> str:
    mapping = {
        "unique_ports>10": "Elevated port-scan breadth (>10 unique ports)",
        "unique_ports>30": "High port-scan breadth (>30 unique ports)",
        "syn_count>50": "SYN flood pattern (>50 SYN packets)",
        "rate>20": "High packet burst rate (>20 pkts/30s)",
        "pps>500_and_packet_count>=20": "Sustained high packets/sec with real packet volume",
    }
    return mapping.get(rule, rule)


def _score_to_severity(score: float) -> str:
    if score >= 85:  return "CRITICAL"
    if score >= 50:  return "HIGH"
    if score >= 20:  return "MEDIUM"
    return "LOW"


def _build_verdict(src_ip: str, final: float, severity: str,
                   top_item, mitre_id: str, mitre_name: str) -> str:
    if final >= 85:
        base = f"CRITICAL threat from {src_ip}"
    elif final >= 50:
        base = f"HIGH-risk activity from {src_ip}"
    elif final >= 20:
        base = f"Moderate-risk event from {src_ip}"
    else:
        base = f"Low-risk event from {src_ip}"

    if top_item is not None and getattr(top_item, "contribution", 0) > 0:
        label = top_item.label
        contrib = top_item.contribution
        verdict = f"{base}. Primary driver: {label} ({contrib:.1f} pts)."
    else:
        verdict = f"{base}."

    if mitre_id:
        verdict += f" Technique: {mitre_id}" + (f" -- {mitre_name}." if mitre_name else ".")
    return verdict


def _build_recommendations(final: float, severity: str,
                            adjustments: List[Dict],
                            contextual_signals: List[Dict],
                            mitre_id: str, trust_type: str) -> List[str]:
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
        recs.append("Log and monitor -- no immediate action required.")

    adj_types = {a["type"] for a in adjustments}
    if "rule_boost" in adj_types:
        recs.append("Review the specific behavioural rule(s) that fired -- see adjustments for detail.")
    if "history_boost" in adj_types:
        recs.append("This is a repeat offender -- consider a standing blocklist entry.")
    if "asset_boost" in adj_types:
        recs.append("Notify the asset owner and verify no unauthorised access occurred.")
    if trust_type in ("trusted_local_discount", "trusted_domain_discount") and final >= 20:
        recs.append("Score was already discounted for a trusted/local source -- treat as higher-confidence if it still cleared this threshold.")

    for cs in contextual_signals:
        if cs["name"] == "threat_intel" and cs["value"] > 0.5:
            recs.append("Cross-reference with external threat intel platforms (VirusTotal, Shodan, AbuseIPDB) -- not yet reflected in the score.")
        if cs["name"] == "uba" and cs["value"] > 0.5:
            recs.append("Review the associated user account for signs of compromise or insider threat (UBA signal, not yet reflected in the score).")

    if mitre_id == "T1486":
        recs.append("Initiate ransomware response playbook immediately.")
    elif mitre_id == "T1041":
        recs.append("Check egress firewall rules and network flows for data exfiltration.")
    elif mitre_id == "T1110":
        recs.append("Enforce account lockout policy and review authentication logs.")

    return recs