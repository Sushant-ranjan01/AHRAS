"""Tests for xai.extended_explainer"""
import pytest
from xai.extended_explainer import ExtendedExplainer, SEVERITY_THRESHOLDS


class TestExtendedExplainer:
    def test_counterfactual_for_critical(self, xai_explainer, sample_explanation):
        cf = xai_explainer.counterfactual(sample_explanation)
        assert cf is not None
        assert cf.target_severity == "HIGH"
        assert cf.feasible is True
        assert cf.delta > 0

    def test_counterfactual_none_for_low(self, xai_explainer):
        low_exp = {
            "final_score": 5.0, "severity": "LOW",
            "components": [{"name": "ml_anomaly", "label": "ML",
                            "raw_value": 0.1, "weight": 15, "contribution": 1.5}],
        }
        assert xai_explainer.counterfactual(low_exp) is None

    def test_all_counterfactuals_walk_down_tiers(self, xai_explainer, sample_explanation):
        cfs = xai_explainer.all_counterfactuals(sample_explanation)
        assert len(cfs) >= 1
        for cf in cfs:
            assert cf.target_severity in [t[0] for t in SEVERITY_THRESHOLDS]

    def test_confidence_high_with_strong_signal(self, xai_explainer, sample_explanation):
        conf = xai_explainer.confidence(sample_explanation, signal_strength=5, history_depth=20)
        assert conf.label in ("HIGH", "MEDIUM")
        assert conf.overall_confidence > 0.4

    def test_confidence_low_with_weak_signal(self, xai_explainer, sample_explanation):
        conf = xai_explainer.confidence(sample_explanation, signal_strength=1, history_depth=0)
        assert conf.label == "LOW"
        assert len(conf.caveats) >= 2

    def test_confidence_caveats_for_disagreeing_components(self, xai_explainer):
        mixed = {
            "final_score": 50.0, "severity": "HIGH",
            "components": [
                {"name": "a", "label": "A", "raw_value": 1.0, "weight": 25, "contribution": 25.0},
                {"name": "b", "label": "B", "raw_value": 0.0, "weight": 25, "contribution": 0.0},
                {"name": "c", "label": "C", "raw_value": 1.0, "weight": 25, "contribution": 25.0},
                {"name": "d", "label": "D", "raw_value": 0.0, "weight": 25, "contribution": 0.0},
            ],
        }
        conf = xai_explainer.confidence(mixed, signal_strength=4, history_depth=10)
        caveat_text = " ".join(conf.caveats).lower()
        assert "disagree" in caveat_text or "mixed" in caveat_text

    def test_feature_importance_returns_ranked_list(self, xai_explainer):
        batch = [
            {"final_score": 90.0, "components": [
                {"name": "threat_intel", "raw_value": 0.9, "weight": 30, "contribution": 27.0},
                {"name": "ml_anomaly",   "raw_value": 1.0, "weight": 15, "contribution": 15.0},
            ]},
            {"final_score": 60.0, "components": [
                {"name": "threat_intel", "raw_value": 0.4, "weight": 30, "contribution": 12.0},
                {"name": "ml_anomaly",   "raw_value": 0.5, "weight": 15, "contribution": 7.5},
            ]},
        ]
        importance = xai_explainer.feature_importance(batch)
        assert len(importance) == 2
        scores = [f.relative_importance for f in importance]
        assert scores == sorted(scores, reverse=True)
        assert importance[0].component == "threat_intel"

    def test_feature_importance_empty_batch(self, xai_explainer):
        result = xai_explainer.feature_importance([])
        assert result == []

    def test_full_report_has_all_keys(self, xai_explainer, sample_explanation):
        report = xai_explainer.full_report(sample_explanation, signal_strength=4, history_depth=10)
        assert "base_explanation" in report
        assert "counterfactual" in report
        assert "confidence" in report
        assert report["confidence"]["label"] in ("HIGH", "MEDIUM", "LOW")

    def test_counterfactual_component_in_explanation(self, xai_explainer, sample_explanation):
        cf = xai_explainer.counterfactual(sample_explanation)
        component_names = [c["name"] for c in sample_explanation["components"]]
        assert cf.component_to_change in component_names

    def test_counterfactual_required_contrib_less_than_current(self, xai_explainer, sample_explanation):
        cf = xai_explainer.counterfactual(sample_explanation)
        if cf and cf.feasible:
            assert cf.required_contribution <= cf.current_contribution
