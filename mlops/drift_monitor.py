"""Persisted drift snapshots for AHRAS model operations."""
from __future__ import annotations
import json, time
from pathlib import Path
from .drift import DriftDetector

class DriftMonitor:
    def __init__(self, path="data/ml_drift.jsonl", threshold=0.20):
        self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True); self.detector=DriftDetector(threshold)
    def record(self, reference, current, feature_names=None, model_version=None):
        report=self.detector.report(reference,current,feature_names); report.update({"timestamp":time.time(),"model_version":model_version})
        with self.path.open("a",encoding="utf-8") as f: f.write(json.dumps(report)+"\n")
        return report
    def latest(self):
        if not self.path.exists(): return None
        lines=self.path.read_text(encoding="utf-8").splitlines()
        return json.loads(lines[-1]) if lines else None
