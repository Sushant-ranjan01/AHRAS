"""Tests for evaluation.metrics"""
import pytest
from evaluation.metrics import MetricsCalculator


class TestMetricsCalculator:

    def _perfect_data(self):
        y_true  = [1]*50 + [0]*50
        y_score = [80.0]*50 + [5.0]*50
        lats    = [0.5] * 100
        return y_true, y_score, lats

    def _all_wrong_data(self):
        y_true  = [1]*50 + [0]*50
        y_score = [5.0]*50 + [80.0]*50
        lats    = [0.5] * 100
        return y_true, y_score, lats

    def test_perfect_classifier_metrics(self, metrics_calc):
        y_true, y_score, lats = self._perfect_data()
        r = metrics_calc.compute(y_true, y_score, lats,
                                 dataset_name="test", threshold=20.0)
        assert r.accuracy  == pytest.approx(1.0, abs=0.001)
        assert r.precision == pytest.approx(1.0, abs=0.001)
        assert r.recall    == pytest.approx(1.0, abs=0.001)
        assert r.f1        == pytest.approx(1.0, abs=0.001)
        assert r.false_positive_rate == pytest.approx(0.0, abs=0.001)
        assert r.detection_rate      == pytest.approx(1.0, abs=0.001)

    def test_all_wrong_classifier(self, metrics_calc):
        y_true, y_score, lats = self._all_wrong_data()
        r = metrics_calc.compute(y_true, y_score, lats,
                                 dataset_name="test", threshold=20.0)
        assert r.true_positives  == 0
        assert r.true_negatives  == 0
        assert r.accuracy        == pytest.approx(0.0, abs=0.001)

    def test_confusion_matrix_adds_up(self, metrics_calc):
        y_true, y_score, lats = self._perfect_data()
        r = metrics_calc.compute(y_true, y_score, lats, threshold=20.0)
        total = r.true_positives + r.false_positives + r.true_negatives + r.false_negatives
        assert total == 100

    def test_auc_near_one_for_perfect_classifier(self, metrics_calc):
        y_true, y_score, lats = self._perfect_data()
        r = metrics_calc.compute(y_true, y_score, lats, threshold=20.0)
        assert r.auc >= 0.99

    def test_auc_near_zero_for_inverted_classifier(self, metrics_calc):
        y_true, y_score, lats = self._all_wrong_data()
        r = metrics_calc.compute(y_true, y_score, lats, threshold=20.0)
        assert r.auc <= 0.01

    def test_latency_stats_computed(self, metrics_calc):
        y_true  = [1, 0, 1, 0]
        y_score = [80.0, 5.0, 80.0, 5.0]
        lats    = [1.0, 2.0, 3.0, 4.0]
        r = metrics_calc.compute(y_true, y_score, lats, threshold=20.0)
        assert r.mean_latency_ms == pytest.approx(2.5, abs=0.01)
        assert r.p95_latency_ms  >= r.mean_latency_ms
        assert r.throughput_eps  > 0

    def test_roc_curve_present(self, metrics_calc):
        y_true, y_score, lats = self._perfect_data()
        r = metrics_calc.compute(y_true, y_score, lats, threshold=20.0)
        assert len(r.roc_fpr) > 0
        assert len(r.roc_tpr) > 0
        assert len(r.roc_fpr) == len(r.roc_tpr)

    def test_per_class_breakdown(self, metrics_calc):
        y_true  = [1, 1, 0, 0]
        y_score = [80.0, 80.0, 5.0, 5.0]
        lats    = [0.5]*4
        cats    = ["Port Scan", "DDoS", "BENIGN", "BENIGN"]
        r = metrics_calc.compute(y_true, y_score, lats, threshold=20.0,
                                 attack_categories=cats)
        assert "Port Scan" in r.per_class
        assert "BENIGN"    in r.per_class

    def test_empty_input_returns_zero_report(self, metrics_calc):
        r = metrics_calc.compute([], [], [], dataset_name="empty")
        assert r.total_samples == 0
        assert r.accuracy == 0.0

    def test_to_dict_has_all_keys(self, metrics_calc):
        y_true, y_score, lats = self._perfect_data()
        r = metrics_calc.compute(y_true, y_score, lats, threshold=20.0)
        d = r.to_dict()
        assert "classification" in d
        assert "performance"    in d
        assert "confusion_matrix" in d
        assert "roc" in d
        cl = d["classification"]
        for key in ["accuracy","precision","recall","f1","auc",
                    "false_positive_rate","detection_rate"]:
            assert key in cl, f"Missing metric: {key}"
        perf = d["performance"]
        for key in ["mean_latency_ms","p95_latency_ms","p99_latency_ms",
                    "throughput_eps","peak_memory_mb","mean_cpu_pct"]:
            assert key in perf, f"Missing perf metric: {key}"
