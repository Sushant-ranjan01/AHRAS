"""Offline evaluation helpers for anomaly models."""
from __future__ import annotations
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

class ModelEvaluator:
    @staticmethod
    def evaluate_scores(y_true, anomaly_scores, threshold=0.5):
        y_true = np.asarray(y_true).astype(int); scores = np.asarray(anomaly_scores, dtype=float)
        y_pred = (scores >= threshold).astype(int)
        out = {
            "samples": int(len(y_true)), "threshold": float(threshold),
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1": float(f1_score(y_true, y_pred, zero_division=0)),
            "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0,1]).tolist(),
        }
        if len(np.unique(y_true)) == 2: out["auc"] = float(roc_auc_score(y_true, scores))
        return out
