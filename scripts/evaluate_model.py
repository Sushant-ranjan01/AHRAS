#!/usr/bin/env python
"""Evaluate a saved sklearn model on .npy features and labels."""
import argparse, json, joblib, numpy as np
from mlops import ModelEvaluator
p=argparse.ArgumentParser(); p.add_argument("model"); p.add_argument("features"); p.add_argument("labels"); p.add_argument("--threshold",type=float,default=0.5); a=p.parse_args()
obj=joblib.load(a.model); pipe=obj.get("pipeline",obj) if isinstance(obj,dict) else obj
X=np.load(a.features); y=np.load(a.labels); raw=-pipe.decision_function(X); lo=float(np.min(raw)); hi=float(np.max(raw)); scores=(raw-lo)/(hi-lo+1e-9)
print(json.dumps(ModelEvaluator.evaluate_scores(y,scores,a.threshold),indent=2))
