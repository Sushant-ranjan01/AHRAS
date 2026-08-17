"""Tests for forecast.predictor"""
import pytest
from forecast.predictor import AttackPredictor, ESCALATION_THRESHOLD


class TestAttackPredictor:
    def test_insufficient_data_returns_gracefully(self, predictor):
        r = predictor.predict("1.1.1.1", [10.0])
        assert r.trend_label == "INSUFFICIENT_DATA"
        assert r.confidence == 0.0
        assert r.forecast_next == []

    def test_escalating_series_detected(self, predictor):
        r = predictor.predict("attacker", [10, 25, 40, 55, 70])
        assert r.trend_label == "ESCALATING"
        assert r.trend > ESCALATION_THRESHOLD

    def test_stable_series_detected(self, predictor):
        r = predictor.predict("stable", [20, 21, 19, 20, 22, 20])
        assert r.trend_label == "STABLE"

    def test_deescalating_series_detected(self, predictor):
        r = predictor.predict("dropping", [80, 65, 50, 35, 20])
        assert r.trend_label == "DE-ESCALATING"
        assert r.trend < -ESCALATION_THRESHOLD

    def test_forecast_length_matches_horizon(self, predictor):
        r = predictor.predict("ip", [10, 20, 30, 40])
        assert len(r.forecast_next) == predictor.horizon

    def test_forecast_values_bounded_0_100(self, predictor):
        r = predictor.predict("ip", [80, 85, 90, 95])
        for v in r.forecast_next:
            assert 0.0 <= v <= 100.0

    def test_breach_detected_for_ramping_series(self, predictor):
        r = predictor.predict("ramping", [50, 60, 70, 80])
        assert r.will_breach_critical is True
        assert r.breach_in_events is not None
        assert r.breach_in_events >= 1

    def test_no_breach_for_low_series(self, predictor):
        r = predictor.predict("low", [5, 6, 7, 5, 6])
        assert r.will_breach_critical is False
        assert r.breach_in_events is None

    def test_top_escalating_ordering(self, predictor):
        fleet = {
            "ip_slow": [10, 12, 14, 16],
            "ip_fast": [10, 25, 45, 65],
            "ip_stable": [20, 21, 20, 21],
        }
        top = predictor.top_escalating(fleet, n=5)
        labels = [r.trend_label for r in top]
        assert all(l == "ESCALATING" for l in labels)
        assert top[0].indicator == "ip_fast"

    def test_confidence_increases_with_more_data(self, predictor):
        short = predictor.predict("ip", [10, 20, 30])
        long  = predictor.predict("ip", [10, 15, 20, 25, 30, 35, 40, 45, 50, 55,
                                         60, 65, 70, 75, 80, 85, 90, 95, 100, 95])
        assert long.confidence > short.confidence

    def test_predict_from_events_dict(self, predictor):
        events = [{"risk_score": v} for v in [10, 20, 30, 40, 55]]
        r = predictor.predict_from_events("ip", events)
        assert r.data_points == 5
        assert r.trend_label in ("ESCALATING", "STABLE", "DE-ESCALATING")
