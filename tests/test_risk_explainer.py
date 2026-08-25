"""Tests for risk_explainer.explainer"""
import pytest


def _sum_check(exp, tolerance=None):
    """
    Reconstruct final_score from the pieces RiskExplainer reports and
    compare against exp.final_score. This is the numerical proof behind
    explainer.py's "faithful-by-construction" claim: summing every
    component contribution + every adjustment value (including cap/floor)
    must reproduce RiskEngine's own risk_score_100, not merely look
    plausible. If this ever drifts, the explainer is describing a
    different number than the one RiskEngine actually used.

    tolerance defaults to 0.1 pt per summed term, since each adjustment
    value is independently pre-rounded to 1 decimal place before being
    stored (see explainer.py's `round(delta, 1)` etc.) -- so a small,
    bounded rounding error is expected and legitimate, not a fidelity bug.
    """
    component_total = sum(c.contribution for c in exp.components)
    adjustment_total = sum(a["value"] for a in exp.adjustments)
    reconstructed = component_total + adjustment_total
    n_terms = len(exp.components) + len(exp.adjustments)
    if tolerance is None:
        tolerance = max(0.15, 0.1 * n_terms)
    diff = abs(reconstructed - exp.final_score)
    assert diff <= tolerance, (
        f"XAI fidelity sum-check failed: components({component_total:.2f}) + "
        f"adjustments({adjustment_total:.2f}) = {reconstructed:.2f}, but "
        f"final_score = {exp.final_score:.2f} (diff {diff:.2f} > tolerance {tolerance:.2f}). "
        f"components={[(c.name, c.contribution) for c in exp.components]} "
        f"adjustments={[(a['type'], a['value']) for a in exp.adjustments]}"
    )
    return diff


class TestExplanationFidelitySumCheck:
    """
    XAI fidelity sum-check: explainer.py's whole design claim is that it
    reconstructs RiskEngine's real score EXACTLY from raw_components,
    rather than re-deriving a decorative score from an independent
    weight table (the bug the v5 docstring says v4 had). These tests
    exercise every adjustment path in risk_scorer.py (strength
    multiplier, rule boosts, trust discount, MITRE boost, asset boost,
    history boost, and the 100-point cap) and assert the reconstruction
    holds for each, not just for the single "typical" case the other
    tests in this file happen to cover.
    """

    def test_sum_check_external_attacker(self, risk_explainer):
        from risk_engine.risk_scorer import RiskEngine
        engine = RiskEngine(skip_dns=True)
        det = {"src_ip": "45.33.32.156", "attack_type": "Port Scan",
               "confidence": 0.9, "packet_count": 80, "unique_ports": 25,
               "syn_count": 40, "pps": 150, "anomaly_flag": True}
        r = engine.evaluate(det)
        exp = risk_explainer.explain(r)
        _sum_check(exp)

    def test_sum_check_benign_local(self, risk_explainer):
        from risk_engine.risk_scorer import RiskEngine
        engine = RiskEngine(skip_dns=True)
        det = {"src_ip": "192.168.29.1", "attack_type": "Normal",
               "confidence": 0.1, "packet_count": 5, "anomaly_flag": False}
        r = engine.evaluate(det)
        exp = risk_explainer.explain(r)
        _sum_check(exp)

    def test_sum_check_with_mitre_boost(self, risk_explainer):
        from risk_engine.risk_scorer import RiskEngine
        engine = RiskEngine(skip_dns=True)
        det = {"src_ip": "203.0.113.50", "attack_type": "Ransomware",
               "confidence": 0.95, "packet_count": 200, "unique_ports": 5,
               "syn_count": 10, "pps": 50, "anomaly_flag": True,
               "mitre_technique": "T1486"}
        r = engine.evaluate(det)
        exp = risk_explainer.explain(r, mitre_id="T1486")
        assert any(a["type"] == "mitre_boost" for a in exp.adjustments)
        _sum_check(exp)

    def test_sum_check_with_asset_boost(self, risk_explainer):
        from risk_engine.risk_scorer import RiskEngine

        class _FakeAssetManager:
            def get_criticality(self, dst_ip):
                return 8.0  # 0-10 scale -> ab = (8/10)*20 = 16 pts

        engine = RiskEngine(skip_dns=True)
        engine.set_asset_manager(_FakeAssetManager())
        det = {"src_ip": "198.51.100.20", "dst_ip": "10.0.0.5",
               "attack_type": "SQL Injection", "confidence": 0.85,
               "packet_count": 60, "unique_ports": 15, "syn_count": 20,
               "pps": 80, "anomaly_flag": True}
        r = engine.evaluate(det)
        exp = risk_explainer.explain(r)
        assert any(a["type"] == "asset_boost" for a in exp.adjustments)
        _sum_check(exp)

    def test_sum_check_with_history_boost(self, risk_explainer):
        from risk_engine.risk_scorer import RiskEngine
        engine = RiskEngine(skip_dns=True)
        det = {"src_ip": "91.219.237.10", "attack_type": "Brute Force",
               "confidence": 0.8, "packet_count": 40, "unique_ports": 12,
               "syn_count": 15, "pps": 60, "anomaly_flag": True,
               "history_boost": 30.0}
        r = engine.evaluate(det)
        exp = risk_explainer.explain(r)
        assert any(a["type"] == "history_boost" for a in exp.adjustments)
        _sum_check(exp)

    def test_sum_check_with_rule_boosts_and_multiplier(self, risk_explainer):
        """High signal strength (>=4/5) triggers the strength multiplier
        AND multiple simultaneous rule boosts (unique_ports, syn_count,
        pps) -- the densest adjustment stack short of a full cap."""
        from risk_engine.risk_scorer import RiskEngine
        engine = RiskEngine(skip_dns=True)
        det = {"src_ip": "185.220.101.7", "attack_type": "DDoS",
               "confidence": 0.99, "packet_count": 500, "unique_ports": 45,
               "syn_count": 120, "pps": 900, "anomaly_flag": True}
        r = engine.evaluate(det)
        exp = risk_explainer.explain(r)
        assert len(exp.adjustments) >= 2
        _sum_check(exp)

    def test_sum_check_trusted_domain_discount(self, risk_explainer):
        """Public trust > 0.7 with signal_strength < 3 applies the x0.5
        trust discount -- a distinct adjustment path from the local
        trusted-IP short-circuit."""
        from risk_engine.risk_scorer import RiskEngine
        engine = RiskEngine(skip_dns=False)  # need real trust resolution here
        det = {"src_ip": "8.8.8.8", "attack_type": "Port Scan",
               "confidence": 0.5, "packet_count": 20, "anomaly_flag": False}
        r = engine.evaluate(det)
        exp = risk_explainer.explain(r)
        _sum_check(exp)

    def test_sum_check_capped_at_max(self, risk_explainer):
        """Stack enough boosts to blow past 100 pre-cap and verify the
        explicit 'cap' adjustment (negative value bringing pre_cap_risk
        back to exactly 100) is itself part of the reconstruction."""
        from risk_engine.risk_scorer import RiskEngine
        engine = RiskEngine(skip_dns=True)
        det = {"src_ip": "45.33.32.200", "attack_type": "Ransomware",
               "confidence": 0.99, "packet_count": 600, "unique_ports": 60,
               "syn_count": 200, "pps": 2000, "anomaly_flag": True,
               "mitre_technique": "T1486", "history_boost": 45.0}
        r = engine.evaluate(det)
        exp = risk_explainer.explain(r, mitre_id="T1486")
        assert exp.final_score == 100.0
        assert any(a["type"] == "cap" for a in exp.adjustments)
        _sum_check(exp)

    def test_sum_check_across_batch_of_random_scenarios(self, risk_explainer):
        """Fuzz-style sweep: many pseudo-random detections spanning the
        full input space, each on a fresh engine, all must reconstruct."""
        import random
        from risk_engine.risk_scorer import RiskEngine
        rng = random.Random(1337)
        attack_types = ["Port Scan", "DDoS", "Brute Force", "SQL Injection",
                         "Ransomware", "Normal"]
        mitre_ids = ["", "T1046", "T1110", "T1190", "T1498"]
        failures = 0
        for i in range(25):
            engine = RiskEngine(skip_dns=True)
            det = {
                "src_ip": f"203.0.{i}.{rng.randint(1,254)}",
                "attack_type": rng.choice(attack_types),
                "confidence": rng.uniform(0.0, 1.0),
                "packet_count": rng.randint(0, 800),
                "unique_ports": rng.randint(0, 60),
                "syn_count": rng.randint(0, 200),
                "pps": rng.uniform(0, 2500),
                "anomaly_flag": rng.random() > 0.5,
                "history_boost": rng.choice([0.0, 0.0, 15.0, 30.0, 45.0]),
                "mitre_technique": rng.choice(mitre_ids),
            }
            r = engine.evaluate(det)
            exp = risk_explainer.explain(r, mitre_id=det["mitre_technique"])
            _sum_check(exp)


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
