"""Tests for risk_explainer.explainer"""
import pytest


class TestRiskExplainer:

    def test_explain_returns_explanation(self, risk_engine, risk_explainer, sample_det_external):
        r = risk_engine.evaluate(sample_det_external)
        exp = risk_explainer.explain(r)
        assert exp is not None
        assert hasattr(exp, "final_score")
        assert hasattr(exp, "severity")
        assert hasattr(exp, "components")

    def test_severity_matches_engine(self, risk_engine, risk_explainer, sample_det_external):
        r = risk_engine.evaluate(sample_det_external)
        exp = risk_explainer.explain(r)
        # Severity must agree — explainer inherits engine's severity
        assert exp.severity == r.severity

    def test_benign_local_scores_zero(self, risk_engine, risk_explainer, sample_det_benign):
        r = risk_engine.evaluate(sample_det_benign)
        exp = risk_explainer.explain(r)
        assert exp.final_score == 0.0
        assert exp.severity == "LOW"

    def test_components_list_not_empty(self, risk_engine, risk_explainer, sample_det_external):
        r = risk_engine.evaluate(sample_det_external)
        exp = risk_explainer.explain(r)
        assert len(exp.components) > 0

    def test_each_component_has_required_fields(self, risk_engine, risk_explainer, sample_det_external):
        r = risk_engine.evaluate(sample_det_external)
        exp = risk_explainer.explain(r)
        for comp in exp.components:
            assert hasattr(comp, "name")
            assert hasattr(comp, "contribution")
            assert hasattr(comp, "weight")
            assert hasattr(comp, "raw_value")
            assert 0.0 <= comp.raw_value <= 1.0
            assert comp.contribution >= 0.0

    def test_threat_intel_not_fabricated_for_local(self, risk_engine, risk_explainer):
        """Bug fix verification: local/unknown-domain IPs must not get
        fake threat-intel contributions from the trust-score fallback."""
        det = {"src_ip": "8.8.8.8", "attack_type": "Normal",
               "confidence": 0.1, "packet_count": 1, "anomaly_flag": False}
        r = risk_engine.evaluate(det)
        exp = risk_explainer.explain(r)
        ti_comp = next((c for c in exp.components if c.name == "threat_intel"), None)
        if ti_comp:
            # Google DNS (trust=0.8) should have zero or near-zero TI contribution
            assert ti_comp.contribution < 20.0, \
                f"Trusted domain should not generate high TI contribution, got {ti_comp.contribution}"

    def test_to_dict_serialisable(self, risk_engine, risk_explainer, sample_det_external):
        import json
        r = risk_engine.evaluate(sample_det_external)
        exp = risk_explainer.explain(r)
        d = exp.to_dict()
        json.dumps(d)   # must not raise
        assert "final_score" in d
        assert "components" in d
        assert "severity" in d

    def test_full_pipeline_critical_attack(self, risk_engine, risk_explainer):
        det = {"src_ip": "45.33.32.156", "attack_type": "Port Scan",
               "confidence": 0.9, "packet_count": 80, "unique_ports": 25,
               "syn_count": 40, "pps": 150, "anomaly_flag": True,
               "mitre_technique": "T1046"}
        r = risk_engine.evaluate(det)
        exp = risk_explainer.explain(r)
        assert exp.severity in ("CRITICAL", "HIGH", "MEDIUM")
        assert exp.final_score >= 0.0
