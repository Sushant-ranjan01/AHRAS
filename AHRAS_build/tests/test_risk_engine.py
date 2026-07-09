"""Tests for risk_engine.risk_scorer"""
import pytest


class TestRiskScorer:
    def test_basic_evaluate_returns_result(self, risk_engine, sample_det_external):
        r = risk_engine.evaluate(sample_det_external)
        assert r is not None
        assert hasattr(r, "risk_score_100")
        assert hasattr(r, "severity")
        assert hasattr(r, "raw_components")

    def test_external_malicious_scores_high(self, risk_engine, sample_det_external):
        r = risk_engine.evaluate(sample_det_external)
        assert r.risk_score_100 >= 20, f"Expected >= 20, got {r.risk_score_100}"

    def test_benign_local_scores_zero(self, risk_engine, sample_det_benign):
        r = risk_engine.evaluate(sample_det_benign)
        assert r.risk_score_100 == 0.0, f"Expected 0 for benign local, got {r.risk_score_100}"

    def test_severity_tiers_consistent(self, risk_engine, sample_det_external):
        r = risk_engine.evaluate(sample_det_external)
        if r.risk_score_100 >= 85:
            assert r.severity == "CRITICAL"
        elif r.risk_score_100 >= 50:
            assert r.severity == "HIGH"
        elif r.risk_score_100 >= 20:
            assert r.severity == "MEDIUM"
        else:
            assert r.severity == "LOW"

    def test_score_capped_at_100(self, risk_engine):
        det = {"src_ip": "1.2.3.4", "attack_type": "Traffic Flood",
               "confidence": 1.0, "packet_count": 9999, "pps": 9999,
               "syn_count": 9999, "anomaly_flag": True, "mitre_technique": "T1498"}
        r = risk_engine.evaluate(det)
        assert r.risk_score_100 <= 100.0

    def test_score_never_negative(self, risk_engine, sample_det_benign):
        r = risk_engine.evaluate(sample_det_benign)
        assert r.risk_score_100 >= 0.0

    def test_private_ip_trust_is_high(self, risk_engine):
        from risk_engine.risk_scorer import _is_private
        assert _is_private("192.168.29.175") is True
        assert _is_private("10.0.0.1") is True
        assert _is_private("172.16.0.50") is True
        assert _is_private("127.0.0.1") is True
        assert _is_private("45.33.32.156") is False
        assert _is_private("8.8.8.8") is False

    def test_raw_components_present(self, risk_engine, sample_det_external):
        r = risk_engine.evaluate(sample_det_external)
        assert isinstance(r.raw_components, dict)
        for key in ["signature", "anomaly", "density", "drift_rate"]:
            assert key in r.raw_components, f"Missing component: {key}"
            assert 0.0 <= r.raw_components[key] <= 1.0

    def test_adaptive_weight_injection(self, risk_engine, weight_learner):
        risk_engine.set_adaptive_learner(weight_learner)
        w = risk_engine._current_weights()
        assert len(w) == 4
        assert abs(sum(w) - 1.0) < 1e-6
        # Reset to no learner for other tests
        risk_engine._adaptive_learner = None

    def test_mitre_boost_increases_score(self, risk_engine):
        base = {"src_ip": "5.5.5.5", "attack_type": "Anomalous Behaviour",
                "confidence": 0.5, "packet_count": 10, "anomaly_flag": True}
        with_mitre = dict(base, mitre_technique="T1486")
        r_base = risk_engine.evaluate(base)
        r_mitre = risk_engine.evaluate(with_mitre)
        assert r_mitre.risk_score_100 >= r_base.risk_score_100
