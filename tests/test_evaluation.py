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

    def test_benign_category_count_reflects_actual_samples(self, metrics_calc):
        """Regression test: BENIGN used to always report count=0 and
        precision/recall/f1=0 because count was computed as tp+fn, which
        are structurally always 0 for a negative class (yt never ==1 for
        benign rows). It should instead report the true sample count and
        specificity/FPR, not zeroed-out attack-style metrics."""
        y_true  = [1, 0, 0, 0]
        y_score = [80.0, 5.0, 5.0, 30.0]   # 1 correct TN, 1 FP among benign
        lats    = [0.5] * 4
        cats    = ["DDoS", "BENIGN", "BENIGN", "BENIGN"]
        r = metrics_calc.compute(y_true, y_score, lats, threshold=20.0,
                                 attack_categories=cats)
        benign = r.per_class["BENIGN"]
        assert benign["count"] == 3
        assert benign["type"] == "benign"
        assert benign["tn"] == 2 and benign["fp"] == 1
        assert benign["specificity"] == pytest.approx(2 / 3, abs=0.001)

        attack = r.per_class["DDoS"]
        assert attack["type"] == "attack"
        assert attack["count"] == 1

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


class TestFeatureToDetectionMapping:
    """Regression tests for evaluation.runner._feature_to_detection.

    Guards against a real bug found during Phase-2 testing: the mapper
    used to fall back to the raw 'Destination Port' NUMBER (e.g. 443,
    8080) as a stand-in for a unique-ports-CONTACTED COUNT whenever no
    aggregate count field was present. Since real destination ports are
    almost always >30, this silently added a flat +80 risk bonus to
    nearly all CICIDS2017-schema traffic regardless of whether it was an
    actual scan, inflating false positives across the board.
    """

    def test_destination_port_number_not_used_as_unique_ports_count(self):
        from evaluation.dataset_loader import DatasetRecord
        from evaluation.runner import _feature_to_detection

        record = DatasetRecord(
            src_ip="203.0.113.5",
            features={"Destination Port": 443, "Total Fwd Packets": 10,
                      "Total Backward Packets": 10},
            label=0, attack_category="benign", raw_row={},
        )
        det = _feature_to_detection(record)
        # A destination port of 443 must NOT be reported as 443 "unique ports"
        assert det["unique_ports"] != 443
        assert det["unique_ports"] == 0

    def test_nslkdd_aggregate_count_field_still_used_when_present(self):
        from evaluation.dataset_loader import DatasetRecord
        from evaluation.runner import _feature_to_detection

        record = DatasetRecord(
            src_ip="203.0.113.5",
            features={"dst_host_srv_count": 45},
            label=1, attack_category="portsweep", raw_row={},
        )
        det = _feature_to_detection(record)
        # A genuine aggregate scan-breadth count field should pass through.
        assert det["unique_ports"] == 45

    def test_single_flow_cicids_record_defaults_to_zero_scan_signal(self):
        from evaluation.dataset_loader import DatasetRecord
        from evaluation.runner import _feature_to_detection

        record = DatasetRecord(
            src_ip="203.0.113.5",
            features={"Destination Port": 61234},  # e.g. an ephemeral/random high port
            label=0, attack_category="benign", raw_row={},
        )
        det = _feature_to_detection(record)
        assert det["unique_ports"] == 0


class TestZeroAttackDayReportIsValidJSON:
    """
    BUG FIX regression tests: a zero-attack day (e.g. a normal Monday capture
    with no attack traffic) has only one class in y_true, so AUC and TPR are
    mathematically undefined (0/0). This used to compute as NaN via sklearn
    and serialize as a literal `NaN` token -- valid to Python's json module,
    but not valid per the JSON spec, and silently misleading (reads as "AUC
    == not-a-number" rather than "not applicable"). It must now report as
    None/null instead, and the whole report must round-trip through strict
    (allow_nan=False) JSON.
    """

    def test_auc_is_none_not_nan_when_only_one_class_present(self, metrics_calc):
        y_true  = [0] * 200          # zero-attack day: every row is benign
        y_score = [5.0] * 200
        lats    = [0.1] * 200
        r = metrics_calc.compute(y_true, y_score, lats,
                                 dataset_name="zero-attack-day", threshold=20.0)
        assert r.auc is None
        assert r.roc_tpr is None

    def test_to_dict_is_valid_strict_json(self, metrics_calc):
        import json
        y_true  = [0] * 200
        y_score = [5.0] * 200
        lats    = [0.1] * 200
        r = metrics_calc.compute(y_true, y_score, lats,
                                 dataset_name="zero-attack-day", threshold=20.0,
                                 attack_categories=["BENIGN"] * 200)
        d = r.to_dict()
        # Must not raise -- allow_nan=False rejects NaN/Infinity outright.
        s = json.dumps(d, allow_nan=False)
        assert '"auc": null' in s or '"auc":null' in s

    def test_two_class_report_still_has_real_auc(self, metrics_calc):
        y_true, y_score, lats = self._perfect_data()
        r = metrics_calc.compute(y_true, y_score, lats,
                                 dataset_name="test", threshold=20.0)
        assert isinstance(r.auc, float)
        assert r.auc >= 0.99

    def _perfect_data(self):
        y_true  = [1]*50 + [0]*50
        y_score = [80.0]*50 + [5.0]*50
        lats    = [0.5] * 100
        return y_true, y_score, lats


class TestCicidsLabelEncodingFix:
    """
    BUG FIX regression test: the public CICIDS2017 CSVs have a well-known
    encoding quirk where a few attack labels (e.g. "Web Attack - Brute
    Force") use an en-dash that's corrupted to U+FFFD (the Unicode
    replacement character) in the dataset's own files. It's cosmetic --
    classification still works because _category_to_attack_type() matches
    on substrings like "brute"/"web", not the dash -- but it must not leak
    into report output.
    """

    def test_clean_label_replaces_replacement_character(self):
        from evaluation.dataset_loader import _clean_label
        assert _clean_label("Web Attack \ufffd Brute Force") == "Web Attack - Brute Force"

    def test_clean_label_leaves_normal_labels_untouched(self):
        from evaluation.dataset_loader import _clean_label
        assert _clean_label("BENIGN") == "BENIGN"
        assert _clean_label("DDoS") == "DDoS"

    def test_clean_label_handles_empty_string(self):
        from evaluation.dataset_loader import _clean_label
        assert _clean_label("") == ""
