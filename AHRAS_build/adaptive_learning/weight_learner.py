"""
AHRAS v4 — Adaptive Risk Weight Learning  (Phase 1 — Research Contribution)
═══════════════════════════════════════════════════════════════════════════
Problem: risk_engine.risk_scorer.RiskEngine uses FIXED weights
  ALPHA (signature) = 0.40
  BETA  (anomaly)   = 0.30
  GAMMA (density)   = 0.20
  DELTA (drift+rate)= 0.10

These were hand-tuned once and never adapt. Two networks behave
differently — what counts as "suspicious packet rate" on a home LAN
is very different from a 500-host enterprise network.

Solution: online gradient-based weight adjustment.
  1. Every case an analyst closes is FEEDBACK:
       resolution == "TRUE_POSITIVE"  → the components that fired
                                          should have scored HIGHER
       resolution == "FALSE_POSITIVE" → the components that fired
                                          should have scored LOWER
  2. We treat this as a tiny online logistic-regression-style update:
       new_weight = old_weight + LR * error * component_raw_value
     where error = (label - predicted_probability)
  3. Weights are re-normalised to sum to 1.0 after every update so the
     risk formula's 0–100 scale is preserved.
  4. Updates are persisted to MongoDB (collection: adaptive_weights) so
     they survive restarts, and there's a rolling history for the
     IEEE paper's "weight convergence over time" plot.

This is intentionally simple (no deep learning, no external libs beyond
numpy which is already a dependency) — defensible in a paper as
"online perceptron-style weight adaptation", reproducible, and fast
enough to run on every case closure without blocking.
"""
import time
import logging
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("ahras.adaptive_learning")

# Component keys must match risk_scorer.py's S, A, T, (B+R) terms
COMPONENT_KEYS = ["signature", "anomaly", "density", "drift_rate"]

DEFAULT_WEIGHTS = {
    "signature":  0.40,   # ALPHA
    "anomaly":    0.30,   # BETA
    "density":    0.20,   # GAMMA
    "drift_rate": 0.10,   # DELTA
}

LEARNING_RATE   = 0.02     # small step — stability over speed
MIN_WEIGHT      = 0.05     # no component can be zeroed out entirely
HISTORY_MAXLEN  = 500


@dataclass
class FeedbackSample:
    """One labeled training sample derived from a closed case."""
    src_ip: str
    label: int                       # 1 = true positive (real threat), 0 = false positive
    components: Dict[str, float]     # raw 0-1 values of S, A, T, (B+R) at time of detection
    predicted_risk: float            # risk score (0-100) that was shown to the analyst
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip, "label": self.label,
            "components": self.components,
            "predicted_risk": round(self.predicted_risk, 1),
            "timestamp": self.timestamp,
        }


class AdaptiveWeightLearner:
    """
    Online weight learner. Call `record_feedback()` whenever a case is
    closed with a TRUE_POSITIVE / FALSE_POSITIVE resolution, and
    `get_weights()` from risk_scorer.py to fetch the current adapted
    weights instead of the hardcoded constants.
    """

    def __init__(self, mongo_collection=None):
        self._lock = threading.Lock()
        self.weights: Dict[str, float] = dict(DEFAULT_WEIGHTS)
        self.history: List[dict] = []          # weight snapshots over time
        self.samples: List[FeedbackSample] = []
        self._col = mongo_collection           # optional MongoDB persistence
        self._total_updates = 0
        self._load_from_db()
        logger.info(f"AdaptiveWeightLearner ready — weights={self.weights}")

    # ── Persistence ──────────────────────────────────────────────────────
    def _load_from_db(self):
        if self._col is None:
            return
        try:
            doc = self._col.find_one({"_doc_type": "current_weights"}, {"_id": 0})
            if doc and "weights" in doc:
                self.weights = doc["weights"]
                self._total_updates = doc.get("total_updates", 0)
                logger.info(f"Loaded adaptive weights from MongoDB: {self.weights}")
            hist_cursor = self._col.find({"_doc_type": "history"}, {"_id": 0}).sort("timestamp", -1).limit(HISTORY_MAXLEN)
            self.history = list(hist_cursor)[::-1]
        except Exception as e:
            logger.warning(f"Could not load adaptive weights: {e}")

    def _persist(self):
        if self._col is None:
            return
        try:
            self._col.update_one(
                {"_doc_type": "current_weights"},
                {"$set": {"weights": self.weights, "total_updates": self._total_updates,
                          "updated_at": time.time()}},
                upsert=True
            )
            self._col.insert_one({
                "_doc_type": "history", "weights": dict(self.weights),
                "timestamp": time.time(), "update_index": self._total_updates,
            })
        except Exception as e:
            logger.warning(f"Could not persist adaptive weights: {e}")

    # ── Core learning step ───────────────────────────────────────────────
    def record_feedback(self, sample: FeedbackSample) -> Dict[str, float]:
        """
        Apply one online update step. Returns the new weight dict.

        Logic: treat predicted_risk/100 as a probability estimate p.
        error = label - p
        For each component, nudge its weight toward reducing the error,
        scaled by how much that component contributed (raw_value).
        """
        with self._lock:
            self.samples.append(sample)
            if len(self.samples) > HISTORY_MAXLEN:
                self.samples.pop(0)

            p = max(0.01, min(0.99, sample.predicted_risk / 100.0))
            error = sample.label - p

            for key in COMPONENT_KEYS:
                raw = sample.components.get(key, 0.0)
                delta = LEARNING_RATE * error * raw
                self.weights[key] = max(MIN_WEIGHT, self.weights[key] + delta)

            # Re-normalize so weights sum to 1.0 (preserves 0-100 risk scale)
            total = sum(self.weights.values())
            if total > 0:
                for key in self.weights:
                    self.weights[key] /= total

            self._total_updates += 1
            self._persist()

            logger.info(
                f"Weight update #{self._total_updates}: src={sample.src_ip} "
                f"label={sample.label} error={error:.3f} -> weights={self._rounded()}"
            )
            return dict(self.weights)

    def get_weights(self) -> Dict[str, float]:
        with self._lock:
            return dict(self.weights)

    def reset_to_defaults(self):
        with self._lock:
            self.weights = dict(DEFAULT_WEIGHTS)
            self._total_updates = 0
            self._persist()
            logger.info("Adaptive weights reset to defaults")

    def _rounded(self) -> Dict[str, float]:
        return {k: round(v, 4) for k, v in self.weights.items()}

    # ── Stats / reporting (for IEEE paper plots) ────────────────────────
    def stats(self) -> dict:
        with self._lock:
            tp = sum(1 for s in self.samples if s.label == 1)
            fp = sum(1 for s in self.samples if s.label == 0)
            return {
                "current_weights":   self._rounded(),
                "default_weights":   DEFAULT_WEIGHTS,
                "total_updates":     self._total_updates,
                "samples_in_buffer": len(self.samples),
                "true_positive_feedback":  tp,
                "false_positive_feedback": fp,
                "drift_from_default": {
                    k: round(self.weights[k] - DEFAULT_WEIGHTS[k], 4)
                    for k in COMPONENT_KEYS
                },
            }

    def weight_history(self, limit: int = 100) -> List[dict]:
        with self._lock:
            return self.history[-limit:]

    def convergence_curve(self) -> List[dict]:
        """Returns weight values at each update — for plotting convergence in the paper."""
        with self._lock:
            return [
                {"update_index": h.get("update_index", i), **h.get("weights", {})}
                for i, h in enumerate(self.history)
            ]
