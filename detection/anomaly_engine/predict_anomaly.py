"""AHRAS — ML Anomaly Predictor (Phase 5b)"""
import os, logging, numpy as np, joblib
from dataclasses import dataclass
from feature_engineering import FeatureVector
from config import config
logger = logging.getLogger("ahras.anomaly")

@dataclass
class AnomalyResult:
    is_anomaly: bool; anomaly_score: float; normalised_score: float; confidence: float; label: str

class AnomalyEngine:
    # Fallback calibration only used if a legacy model file (raw pipeline,
    # no stored calibration) is loaded and we can't retrain. This mirrors
    # the old hard-coded behaviour and is intentionally *not* relied upon
    # for new models -- see train_model.py.
    _FALLBACK_LO, _FALLBACK_HI = -0.5, 0.5

    def __init__(self, model_path=None):
        self.model_path = model_path or config.MODEL_PATH
        self._pipe = None
        self._score_lo = self._FALLBACK_LO
        self._score_hi = self._FALLBACK_HI
        self._load()

    def predict(self, vec: FeatureVector) -> AnomalyResult:
        return self._score(vec.values.reshape(1,-1))[0]

    def _load(self):
        if os.path.exists(self.model_path):
            try:
                obj = joblib.load(self.model_path)
                if isinstance(obj, dict) and "pipeline" in obj:
                    self._pipe = obj["pipeline"]
                    self._score_lo = float(obj.get("score_lo", self._FALLBACK_LO))
                    self._score_hi = float(obj.get("score_hi", self._FALLBACK_HI))
                    if self._score_hi <= self._score_lo:
                        self._score_hi = self._score_lo + 1e-6
                else:
                    # Legacy model file saved before calibration was added --
                    # retrain so we get both a fresh model AND calibration
                    # instead of silently falling back to the broken
                    # hard-coded [-0.5, 0.5] normalisation window.
                    logger.warning(
                        "Legacy uncalibrated model at %s -- retraining to add "
                        "score calibration.", self.model_path
                    )
                    from detection.anomaly_engine.train_model import train
                    self._pipe = train(output_path=self.model_path)
                    obj2 = joblib.load(self.model_path)
                    self._score_lo = float(obj2["score_lo"])
                    self._score_hi = float(obj2["score_hi"])
                logger.info("Model loaded (score_lo=%.4f, score_hi=%.4f)", self._score_lo, self._score_hi)
                return
            except Exception:
                logger.exception("Failed to load model at %s, retraining", self.model_path)
        from detection.anomaly_engine.train_model import train
        self._pipe = train(output_path=self.model_path)
        obj = joblib.load(self.model_path)
        self._score_lo = float(obj["score_lo"])
        self._score_hi = float(obj["score_hi"])

    def _score(self, X):
        preds = self._pipe.predict(X); scores = self._pipe.decision_function(X)
        span = self._score_hi - self._score_lo
        out=[]
        for p,s in zip(preds,scores):
            # Stretch decision_function's *actual* observed range (calibrated
            # against the training baseline) to the full [0, 1] band, instead
            # of assuming a fixed +/-0.5 window that real IsolationForest
            # scores rarely fill. See train_model.py for why this matters.
            norm = float(np.clip((self._score_hi - s) / span, 0, 1))
            conf = abs(norm-0.5)*2
            out.append(AnomalyResult(p==-1, float(s), norm, min(conf,1.0), "Anomalous" if p==-1 else "Normal"))
        return out
