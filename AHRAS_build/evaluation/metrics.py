"""
AHRAS v4 -- Metrics Calculator
================================
Computes all 11 requested evaluation metrics from ground-truth labels
and predicted labels/scores:
  1.  Accuracy
  2.  Precision
  3.  Recall
  4.  F1 Score
  5.  ROC Curve  (thresholds + TPR/FPR arrays)
  6.  AUC        (Area Under ROC Curve)
  7.  False Positive Rate (FPR)
  8.  Detection Rate (= Recall / True Positive Rate)
  9.  Latency     (per-sample processing time, ms)
  10. CPU Usage   (% during evaluation run)
  11. Memory      (peak RSS MB during evaluation run)
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import logging

logger = logging.getLogger("ahras.evaluation.metrics")


@dataclass
class MetricsReport:
    # Core classification metrics
    accuracy:           float = 0.0
    precision:          float = 0.0
    recall:             float = 0.0
    f1:                 float = 0.0
    auc:                float = 0.0
    false_positive_rate: float = 0.0
    detection_rate:     float = 0.0   # == recall / TPR

    # Confusion matrix
    true_positives:     int = 0
    false_positives:    int = 0
    true_negatives:     int = 0
    false_negatives:    int = 0
    total_samples:      int = 0

    # Performance
    mean_latency_ms:    float = 0.0
    p95_latency_ms:     float = 0.0
    p99_latency_ms:     float = 0.0
    throughput_eps:     float = 0.0   # events per second
    peak_memory_mb:     float = 0.0
    mean_cpu_pct:       float = 0.0

    # ROC (sampled for serialisability)
    roc_fpr:            List[float] = field(default_factory=list)
    roc_tpr:            List[float] = field(default_factory=list)

    # Per-class breakdown
    per_class:          Dict[str, dict] = field(default_factory=dict)

    # Dataset metadata
    dataset_name:       str = ""
    num_benign:         int = 0
    num_attack:         int = 0
    threshold_used:     float = 0.5

    def to_dict(self) -> dict:
        return {
            "dataset": self.dataset_name,
            "samples": {
                "total": self.total_samples,
                "benign": self.num_benign,
                "attack": self.num_attack,
            },
            "classification": {
                "accuracy":            round(self.accuracy, 4),
                "precision":           round(self.precision, 4),
                "recall":              round(self.recall, 4),
                "f1":                  round(self.f1, 4),
                "auc":                 round(self.auc, 4),
                "false_positive_rate": round(self.false_positive_rate, 4),
                "detection_rate":      round(self.detection_rate, 4),
            },
            "confusion_matrix": {
                "TP": self.true_positives,  "FP": self.false_positives,
                "TN": self.true_negatives,  "FN": self.false_negatives,
            },
            "performance": {
                "mean_latency_ms":  round(self.mean_latency_ms, 3),
                "p95_latency_ms":   round(self.p95_latency_ms, 3),
                "p99_latency_ms":   round(self.p99_latency_ms, 3),
                "throughput_eps":   round(self.throughput_eps, 1),
                "peak_memory_mb":   round(self.peak_memory_mb, 1),
                "mean_cpu_pct":     round(self.mean_cpu_pct, 1),
            },
            "roc": {
                "fpr": self.roc_fpr,
                "tpr": self.roc_tpr,
            },
            "per_class": self.per_class,
            "threshold_used": self.threshold_used,
        }

    def summary_line(self) -> str:
        return (
            f"[{self.dataset_name}] "
            f"Acc={self.accuracy:.3f} P={self.precision:.3f} "
            f"R={self.recall:.3f} F1={self.f1:.3f} AUC={self.auc:.3f} "
            f"FPR={self.false_positive_rate:.3f} DR={self.detection_rate:.3f} "
            f"Lat={self.mean_latency_ms:.1f}ms CPU={self.mean_cpu_pct:.1f}% "
            f"Mem={self.peak_memory_mb:.0f}MB"
        )


class MetricsCalculator:
    """
    Computes MetricsReport from two parallel lists:
      y_true  : List[int]   -- ground truth (0=benign, 1=attack)
      y_score : List[float] -- raw risk score 0-100 from AHRAS
      latencies_ms : List[float] -- per-sample processing times

    Uses scikit-learn only for ROC/AUC (already in requirements.txt).
    All other metrics are computed from the confusion matrix directly --
    no black-box library, defensible in a paper.
    """

    def compute(
        self,
        y_true: List[int],
        y_score: List[float],
        latencies_ms: List[float],
        peak_memory_mb: float = 0.0,
        mean_cpu_pct: float = 0.0,
        dataset_name: str = "unknown",
        threshold: float = 20.0,     # risk_score_100 >= threshold => predicted attack
        attack_categories: Optional[List[str]] = None,
    ) -> MetricsReport:

        if not y_true:
            logger.warning("Empty y_true — cannot compute metrics")
            return MetricsReport(dataset_name=dataset_name)

        n = len(y_true)
        y_pred = [1 if s >= threshold else 0 for s in y_score]

        # -- Confusion matrix --
        tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
        fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
        tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
        fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

        accuracy  = (tp + tn) / n if n else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall    = tp / (tp + fn) if (tp + fn) else 0.0   # == detection rate
        f1        = (2 * precision * recall / (precision + recall)
                     if (precision + recall) else 0.0)
        fpr       = fp / (fp + tn) if (fp + tn) else 0.0

        # -- ROC / AUC --
        roc_fpr, roc_tpr, auc_val = self._roc_auc(y_true, y_score)

        # -- Latency stats --
        mean_lat, p95_lat, p99_lat, throughput = self._latency_stats(latencies_ms)

        # -- Per-class breakdown --
        per_class = {}
        if attack_categories:
            cats: Dict[str, Dict[str, int]] = {}
            for yt, yp, cat in zip(y_true, y_pred, attack_categories):
                c = cat.strip() or "Unknown"
                if c not in cats:
                    cats[c] = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
                key = ("tp" if yt == 1 and yp == 1 else
                       "fp" if yt == 0 and yp == 1 else
                       "tn" if yt == 0 and yp == 0 else "fn")
                cats[c][key] += 1
            for cat, cm in cats.items():
                _tp, _fp, _fn = cm["tp"], cm["fp"], cm["fn"]
                _p = _tp / (_tp + _fp) if (_tp + _fp) else 0.0
                _r = _tp / (_tp + _fn) if (_tp + _fn) else 0.0
                _f = 2*_p*_r/(_p+_r) if (_p+_r) else 0.0
                per_class[cat] = {
                    "precision": round(_p, 3), "recall": round(_r, 3),
                    "f1": round(_f, 3), "count": _tp + _fn,
                    **{k: v for k, v in cm.items()},
                }

        return MetricsReport(
            accuracy=accuracy, precision=precision, recall=recall, f1=f1,
            auc=auc_val, false_positive_rate=fpr, detection_rate=recall,
            true_positives=tp, false_positives=fp,
            true_negatives=tn, false_negatives=fn,
            total_samples=n,
            num_benign=sum(1 for y in y_true if y == 0),
            num_attack=sum(1 for y in y_true if y == 1),
            mean_latency_ms=mean_lat, p95_latency_ms=p95_lat,
            p99_latency_ms=p99_lat, throughput_eps=throughput,
            peak_memory_mb=peak_memory_mb, mean_cpu_pct=mean_cpu_pct,
            roc_fpr=roc_fpr, roc_tpr=roc_tpr,
            per_class=per_class, dataset_name=dataset_name,
            threshold_used=threshold,
        )

    def _roc_auc(self, y_true, y_score):
        try:
            from sklearn.metrics import roc_curve, auc
            fpr_arr, tpr_arr, _ = roc_curve(y_true, y_score)
            auc_val = float(auc(fpr_arr, tpr_arr))
            # Downsample to 50 points for JSON serialisability
            step = max(1, len(fpr_arr) // 50)
            return (
                [round(float(x), 4) for x in fpr_arr[::step]],
                [round(float(x), 4) for x in tpr_arr[::step]],
                round(auc_val, 4),
            )
        except Exception as e:
            logger.warning(f"ROC/AUC calculation failed: {e}")
            return [], [], 0.0

    def _latency_stats(self, latencies_ms):
        if not latencies_ms:
            return 0.0, 0.0, 0.0, 0.0
        s = sorted(latencies_ms)
        n = len(s)
        mean = sum(s) / n
        p95  = s[int(n * 0.95)]
        p99  = s[min(int(n * 0.99), n - 1)]
        total_s = sum(latencies_ms) / 1000.0
        throughput = n / total_s if total_s > 0 else 0.0
        return round(mean, 3), round(p95, 3), round(p99, 3), round(throughput, 1)
