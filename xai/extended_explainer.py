"""
AHRAS v4 -- Extended Explainable AI  (Phase 1 -- Research Contribution)
=========================================================================
risk_explainer.explainer.RiskExplainer already breaks the 0-100 score into
5 weighted components with reasons. That answers "what contributed to this
score". This module answers three further questions an IEEE-grade XAI
section needs:

1. FEATURE IMPORTANCE (global): across MANY decisions, which components
   tend to drive the final verdict? Computed via normalized contribution
   variance across a batch of explanations -- analogous to permutation
   importance but derived analytically (no retraining needed) since our
   risk function is a known closed-form weighted sum, not a black box.

2. COUNTERFACTUAL EXPLANATION (local): "what is the SMALLEST change to
   this specific event that would flip the verdict to the next severity
   tier down?" e.g. "If threat_intel contribution dropped from 24/30 to
   under 9/30, severity would drop from CRITICAL to HIGH." This is the
   single most analyst-actionable XAI output -- it tells you exactly
   which signal to investigate/suppress to neutralize a false positive,
   or which signal is irreducibly driving a true positive.

3. CONFIDENCE / UNCERTAINTY: how much do we trust this explanation?
   Built from (a) signal_strength -- how many independent detectors
   agreed, (b) component agreement -- do the components point the same
   direction or contradict each other, (c) data sufficiency -- was this
   based on a thin history (1-2 events) or a robust one (20+).

Why this design is defensible for a paper: because AHRAS's risk function
is fully known (R = sum of weighted, bounded components, see
risk_engine.risk_scorer), we don't need approximate methods like SHAP/LIME
that perturb a black-box model. We can compute EXACT feature attribution
and EXACT counterfactual boundaries analytically. This is strictly more
faithful than SHAP for this specific model class, and is worth stating
explicitly in the paper as a design choice, not a limitation.
"""
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger("ahras.xai")

SEVERITY_THRESHOLDS = [("CRITICAL", 85), ("HIGH", 50), ("MEDIUM", 20), ("LOW", 0)]


@dataclass
class Counterfactual:
    target_severity: str           # the next tier down
    component_to_change: str       # which component, if reduced, gets us there
    current_contribution: float
    required_contribution: float   # what it would need to be
    required_raw_value: float      # 0-1 raw value needed
    delta: float                   # how much it needs to drop
    feasible: bool                 # is this a realistic ask (delta within [0, current])
    explanation: str

    def to_dict(self) -> dict:
        return {
            "target_severity": self.target_severity,
            "component": self.component_to_change,
            "current_contribution": round(self.current_contribution, 1),
            "required_contribution": round(self.required_contribution, 1),
            "required_raw_value": round(self.required_raw_value, 3),
            "delta": round(self.delta, 1),
            "feasible": self.feasible,
            "explanation": self.explanation,
        }


@dataclass
class ConfidenceAssessment:
    overall_confidence: float          # 0-1
    signal_agreement: float            # 0-1 -- do components agree on direction
    data_sufficiency: float            # 0-1 -- based on signal_strength / history depth
    label: str                         # HIGH / MEDIUM / LOW confidence
    caveats: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "overall_confidence": round(self.overall_confidence, 3),
            "signal_agreement": round(self.signal_agreement, 3),
            "data_sufficiency": round(self.data_sufficiency, 3),
            "label": self.label,
            "caveats": self.caveats,
        }


@dataclass
class FeatureImportance:
    """Global importance across a batch of explanations."""
    component: str
    mean_contribution: float
    contribution_variance: float
    times_dominant: int             # how often this was the top contributor
    relative_importance: float      # 0-1, normalized

    def to_dict(self) -> dict:
        return {
            "component": self.component,
            "mean_contribution": round(self.mean_contribution, 2),
            "contribution_variance": round(self.contribution_variance, 2),
            "times_dominant": self.times_dominant,
            "relative_importance": round(self.relative_importance, 3),
        }


class ExtendedExplainer:
    """
    Wraps risk_explainer.RiskExplanation objects (or their .to_dict()
    output) to add counterfactual reasoning, confidence scoring, and
    batch-level feature importance -- without modifying the base
    RiskExplainer, which stays the source of truth for the score
    breakdown itself.
    """

    def __init__(self):
        logger.info("ExtendedExplainer ready")

    # -- 1. Counterfactual explanation ---------------------------------------
    def counterfactual(self, explanation_dict: dict) -> Optional[Counterfactual]:
        """
        Given a RiskExplanation.to_dict() output, compute the smallest
        single-component change that would drop the verdict to the next
        severity tier down. Returns None if already at LOWEST tier.
        """
        final = explanation_dict.get("final_score", 0.0)
        components = explanation_dict.get("components", [])
        if not components:
            return None

        current_tier_idx = self._tier_index(final)
        if current_tier_idx >= len(SEVERITY_THRESHOLDS) - 1:
            return None  # already LOW, no lower tier to fall to

        target_label, target_threshold = SEVERITY_THRESHOLDS[current_tier_idx + 1]
        # We need final_score to drop just under the CURRENT tier's lower bound
        current_label, current_threshold = SEVERITY_THRESHOLDS[current_tier_idx]
        points_to_remove = (final - current_threshold) + 0.5  # cross below boundary

        # Find the component whose full contribution is closest to (but
        # ideally exceeds) the points we need to remove -- minimal-change
        # counterfactual: prefer the SMALLEST sufficient single change.
        candidates = []
        for c in components:
            contrib = c.get("contribution", 0.0)
            weight = c.get("weight", 1)
            if contrib >= points_to_remove and weight > 0:
                required_contrib = max(0.0, contrib - points_to_remove)
                required_raw = required_contrib / weight if weight else 0.0
                candidates.append((c, required_contrib, required_raw))

        if not candidates:
            # No single component is sufficient alone -- report the
            # largest contributor as the primary lever, flagged infeasible
            # as a single-component change.
            biggest = max(components, key=lambda c: c.get("contribution", 0.0))
            return Counterfactual(
                target_severity=target_label,
                component_to_change=biggest.get("name", "unknown"),
                current_contribution=biggest.get("contribution", 0.0),
                required_contribution=0.0,
                required_raw_value=0.0,
                delta=biggest.get("contribution", 0.0),
                feasible=False,
                explanation=(
                    f"No single component alone explains enough of the score to drop "
                    f"to {target_label} -- multiple components would need to change "
                    f"together. Largest single lever: {biggest.get('label', biggest.get('name'))}."
                ),
            )

        # Pick the candidate requiring the SMALLEST delta (least drastic, most actionable)
        candidates.sort(key=lambda x: x[0]["contribution"] - x[1])
        comp, required_contrib, required_raw = candidates[0]
        delta = comp["contribution"] - required_contrib

        return Counterfactual(
            target_severity=target_label,
            component_to_change=comp.get("name", "unknown"),
            current_contribution=comp["contribution"],
            required_contribution=required_contrib,
            required_raw_value=required_raw,
            delta=delta,
            feasible=True,
            explanation=(
                f"If '{comp.get('label', comp.get('name'))}' contribution dropped from "
                f"{comp['contribution']:.1f} to {required_contrib:.1f} pts "
                f"(raw value {comp.get('raw_value',0):.2f} -> {required_raw:.2f}), "
                f"severity would fall from {current_label} to {target_label}."
            ),
        )

    def all_counterfactuals(self, explanation_dict: dict) -> List[Counterfactual]:
        """Counterfactuals for EVERY lower tier, not just the next one --
        useful for a 'how far would this need to go to be fully cleared' view."""
        results = []
        final = explanation_dict.get("final_score", 0.0)
        current_idx = self._tier_index(final)
        # temporarily walk down each tier by recomputing with a modified copy
        working = dict(explanation_dict)
        for _ in range(current_idx, len(SEVERITY_THRESHOLDS) - 1):
            cf = self.counterfactual(working)
            if cf is None:
                break
            results.append(cf)
            if not cf.feasible:
                break
            # Simulate applying this counterfactual for the next iteration
            working = dict(working)
            working["final_score"] = SEVERITY_THRESHOLDS[self._tier_index(working["final_score"]) + 1][1] - 0.5
        return results

    # -- 2. Confidence / uncertainty -----------------------------------------
    def confidence(self, explanation_dict: dict, signal_strength: int = 0,
                   history_depth: int = 0) -> ConfidenceAssessment:
        """
        signal_strength: 0-5, how many independent detectors fired
        history_depth: how many prior events exist for this indicator
        """
        components = explanation_dict.get("components", [])
        caveats = []

        # Signal agreement: do components broadly agree (most high or most low)
        # vs contradict (some very high, some very low)?
        raws = [c.get("raw_value", 0.0) for c in components]
        if raws:
            mean_raw = sum(raws) / len(raws)
            spread = sum(abs(r - mean_raw) for r in raws) / len(raws)
            agreement = max(0.0, 1.0 - spread * 2)  # spread of 0.5 -> 0 agreement
        else:
            agreement = 0.0
            caveats.append("No component data available for agreement scoring")

        # Data sufficiency
        sig_conf = min(1.0, signal_strength / 5.0)
        hist_conf = min(1.0, history_depth / 10.0)
        data_sufficiency = 0.6 * sig_conf + 0.4 * hist_conf

        if signal_strength < 2:
            caveats.append(f"Only {signal_strength}/5 independent signals fired -- low corroboration")
        if history_depth < 3:
            caveats.append(f"Only {history_depth} prior events for this indicator -- thin history")
        if agreement < 0.4:
            caveats.append("Components disagree significantly -- mixed signal, verify manually")

        overall = round(0.5 * agreement + 0.5 * data_sufficiency, 3)
        # Hard cap: very low signal corroboration or near-zero history
        # should never be reported as anything above LOW, regardless of
        # how "consistent" the (thin) data happens to look.
        if signal_strength < 2 or history_depth == 0:
            overall = min(overall, 0.39)

        if overall >= 0.7:
            label = "HIGH"
        elif overall >= 0.4:
            label = "MEDIUM"
        else:
            label = "LOW"

        return ConfidenceAssessment(
            overall_confidence=overall, signal_agreement=round(agreement, 3),
            data_sufficiency=round(data_sufficiency, 3), label=label, caveats=caveats,
        )

    # -- 3. Batch / global feature importance --------------------------------
    def feature_importance(self, explanation_dicts: List[dict]) -> List[FeatureImportance]:
        """
        Run across a BATCH of past explanations (e.g. last 100 events) to
        compute which components most often drive the final verdict.
        This is the closest analogue to permutation feature importance,
        computed exactly (not approximated) since contributions are
        already known per-event.
        """
        if not explanation_dicts:
            return []

        agg: Dict[str, List[float]] = {}
        dominant_count: Dict[str, int] = {}

        for exp in explanation_dicts:
            comps = exp.get("components", [])
            if not comps:
                continue
            for c in comps:
                name = c.get("name", "unknown")
                agg.setdefault(name, []).append(c.get("contribution", 0.0))
            top = max(comps, key=lambda c: c.get("contribution", 0.0))
            dominant_count[top.get("name", "unknown")] = dominant_count.get(top.get("name", "unknown"), 0) + 1

        results = []
        total_mean = sum(sum(v) / len(v) for v in agg.values()) or 1.0
        for name, contributions in agg.items():
            mean_c = sum(contributions) / len(contributions)
            variance = sum((x - mean_c) ** 2 for x in contributions) / len(contributions)
            results.append(FeatureImportance(
                component=name, mean_contribution=mean_c,
                contribution_variance=variance,
                times_dominant=dominant_count.get(name, 0),
                relative_importance=mean_c / total_mean,
            ))

        results.sort(key=lambda r: r.relative_importance, reverse=True)
        return results

    # -- Internals ------------------------------------------------------------
    def _tier_index(self, score: float) -> int:
        for i, (label, threshold) in enumerate(SEVERITY_THRESHOLDS):
            if score >= threshold:
                return i
        return len(SEVERITY_THRESHOLDS) - 1

    def full_report(self, explanation_dict: dict, signal_strength: int = 0,
                    history_depth: int = 0) -> dict:
        """Convenience -- bundles counterfactual + confidence into one
        response, the typical shape the dashboard / API will want."""
        cf = self.counterfactual(explanation_dict)
        conf = self.confidence(explanation_dict, signal_strength, history_depth)
        return {
            "base_explanation": explanation_dict,
            "counterfactual": cf.to_dict() if cf else None,
            "confidence": conf.to_dict(),
        }
