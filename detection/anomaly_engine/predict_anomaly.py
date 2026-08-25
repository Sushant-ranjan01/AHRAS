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
    def __init__(self, model_path=None):
        self.model_path = model_path or config.MODEL_PATH
        self._pipe = None; self._load()

    def predict(self, vec: FeatureVector) -> AnomalyResult:
        return self._score(vec.values.reshape(1,-1))[0]

    def _load(self):
        if os.path.exists(self.model_path):
            try: self._pipe = joblib.load(self.model_path); logger.info("Model loaded"); return
            except: pass
        from detection.anomaly_engine.train_model import train
        self._pipe = train(output_path=self.model_path)

    def _score(self, X):
        preds = self._pipe.predict(X); scores = self._pipe.decision_function(X)
        out=[]
        for p,s in zip(preds,scores):
            norm = float(np.clip((0.5-s)/1.0,0,1)); conf=abs(norm-0.5)*2
            out.append(AnomalyResult(p==-1, float(s), norm, min(conf,1.0), "Anomalous" if p==-1 else "Normal"))
        return out
