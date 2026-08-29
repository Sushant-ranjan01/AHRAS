import json
import numpy as np
from mlops.drift import DriftDetector
from mlops.feedback import FeedbackStore
from mlops.evaluator import ModelEvaluator

def test_psi_no_drift_for_same_distribution():
    rng=np.random.default_rng(1); x=rng.normal(size=(500,3))
    report=DriftDetector().report(x,x, ["a","b","c"])
    assert not report["drift_detected"]

def test_feedback_persists(tmp_path):
    f=FeedbackStore(tmp_path/"feedback.jsonl")
    f.add(alert_id="A1",label=1,model_version="v1")
    f.add(alert_id="A2",label=0,model_version="v1")
    assert f.summary()["total"]==2
    assert f.summary()["by_model"]["v1"]["false_positive"]==1

def test_evaluator_returns_metrics():
    out=ModelEvaluator.evaluate_scores([0,0,1,1],[.1,.2,.8,.9])
    assert out["f1"]==1.0
    assert out["auc"]==1.0
