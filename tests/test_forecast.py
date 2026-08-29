"""Tests for forecast.predictor"""
import pytest
from forecast.predictor import (
    AttackPredictor, ESCALATION_THRESHOLD, MIN_POINTS_FOR_FORECAST,
    forecast_accuracy, threshold_crossing_lead_time, walk_forward_errors,
)


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


class TestForecastAccuracyMAERMSE:
    """
    Walk-forward, causal one-step-ahead accuracy: forecast_accuracy()
    must never peek at series[t] when scoring the forecast made from
    series[:t] -- and its numbers should behave sensibly (near-zero
    error on a flat series, well-defined and non-negative always,
    zero-record fallback for too-short series rather than raising).
    """

    def test_zero_error_on_perfectly_flat_series(self, predictor):
        series = [40.0] * 10
        result = forecast_accuracy(predictor, series)
        # Holt's method on a constant series converges to that constant
        # within a step or two -- allow a small settling-in tolerance.
        assert result["n"] == len(series) - MIN_POINTS_FOR_FORECAST
        assert result["mae"] < 1.0
        assert result["rmse"] < 1.0

    def test_insufficient_data_returns_zero_record_not_error(self, predictor):
        result = forecast_accuracy(predictor, [10.0, 20.0])  # < MIN_POINTS_FOR_FORECAST + 1
        assert result == {"n": 0, "mae": 0.0, "rmse": 0.0}

    def test_n_matches_number_of_causal_forecasts(self, predictor):
        series = [10, 15, 22, 30, 41, 55, 70, 88]
        result = forecast_accuracy(predictor, series)
        assert result["n"] == len(series) - MIN_POINTS_FOR_FORECAST

    def test_rmse_at_least_mae(self, predictor):
        """RMSE >= MAE always holds mathematically (RMSE penalizes large
        errors more) -- a basic sanity invariant on any noisy series."""
        series = [10, 40, 15, 60, 5, 90, 20, 75, 30, 55]
        result = forecast_accuracy(predictor, series)
        assert result["n"] > 0
        assert result["rmse"] >= result["mae"] - 1e-9

    def test_walk_forward_errors_length_matches_forecast_accuracy_n(self, predictor):
        series = [12, 18, 27, 33, 44, 52, 61, 70, 82, 91]
        errors = walk_forward_errors(predictor, series)
        result = forecast_accuracy(predictor, series)
        assert len(errors) == result["n"]
        # Cross-check forecast_accuracy's MAE/RMSE are actually derived
        # from these exact errors, not some independently-recomputed number.
        import math
        expected_mae = sum(abs(e) for e in errors) / len(errors)
        expected_rmse = math.sqrt(sum(e * e for e in errors) / len(errors))
        assert result["mae"] == round(expected_mae, 3)
        assert result["rmse"] == round(expected_rmse, 3)

    def test_errors_are_causal_not_influenced_by_future_values(self, predictor):
        """Two series that are IDENTICAL up through index t must produce
        the identical forecast (and thus identical error) AT index t,
        regardless of what happens afterward -- proof there's no
        lookahead into series[t+1:]."""
        shared_prefix = [10, 16, 24, 33, 42]
        series_a = shared_prefix + [50, 60, 70]          # continues ramping
        series_b = shared_prefix + [5, 2, 0]              # then crashes
        errors_a = walk_forward_errors(predictor, series_a)
        errors_b = walk_forward_errors(predictor, series_b)
        # The first (len(shared_prefix) - MIN_POINTS_FOR_FORECAST) errors
        # were computed entirely from the shared prefix and must match.
        n_shared_forecasts = len(shared_prefix) - MIN_POINTS_FOR_FORECAST
        assert errors_a[:n_shared_forecasts] == errors_b[:n_shared_forecasts]


class TestThresholdCrossingLeadTime:
    """
    Early-warning usefulness: for a series that genuinely escalates into
    CRITICAL territory, threshold_crossing_lead_time() should find a
    causal forecast that warned BEFORE the real crossing -- and must
    return None (not a fabricated number) whenever there's nothing
    meaningful to report.
    """

    def test_positive_lead_time_for_escalating_series(self, predictor):
        series = [5, 8, 12, 20, 35, 55, 80, 95]
        lead = threshold_crossing_lead_time(predictor, series)
        assert lead is not None
        assert lead >= 1

    def test_none_for_series_that_never_crosses(self, predictor):
        series = [5, 6, 7, 6, 5, 8, 7, 6]
        lead = threshold_crossing_lead_time(predictor, series)
        assert lead is None

    def test_none_when_crossing_happens_before_forecast_possible(self, predictor):
        """If the series is already >= threshold before MIN_POINTS_FOR_
        FORECAST events exist, there was no way to have warned in time --
        must report None, not a misleading 0."""
        series = [90.0, 92.0]  # crosses at index 0, before min_points=3
        lead = threshold_crossing_lead_time(predictor, series)
        assert lead is None

    def test_none_for_a_genuine_forecaster_miss(self, predictor):
        """A step-function jump straight to CRITICAL with no ramp-up at
        all should NOT be creditied with a lead time the forecaster never
        actually earned -- Holt's method has no basis to predict a
        sudden jump from a flat history."""
        series = [10, 10, 10, 10, 95]
        lead = threshold_crossing_lead_time(predictor, series)
        assert lead is None

    def test_lead_time_uses_custom_threshold(self, predictor):
        """
        Regression test: ForecastResult.will_breach_critical is hardcoded
        to CRITICAL (85) inside AttackPredictor.predict(), so
        threshold_crossing_lead_time() must NOT rely on that flag when a
        caller passes a different threshold -- it has to check
        forecast_next against the actual `threshold` argument. A steep,
        steadily-widening ramp lets a lower threshold be reached (and
        warned about) with a different lead time than a higher one,
        proving the parameter genuinely changes the crossing point that
        gets timed, not just which flag gets read.
        """
        series = [2, 4, 8, 14, 22, 32, 44, 58, 74, 92, 100, 100]
        wide_predictor = AttackPredictor(horizon=8)
        lead_low = threshold_crossing_lead_time(wide_predictor, series, threshold=30.0)
        lead_mid = threshold_crossing_lead_time(wide_predictor, series, threshold=60.0)
        lead_high = threshold_crossing_lead_time(wide_predictor, series, threshold=90.0)
        assert lead_low is not None
        assert lead_mid is not None
        assert lead_high is not None
        # Different thresholds -> different actual-crossing events -> the
        # function is genuinely responding to the passed-in threshold.
        assert len({lead_low, lead_mid, lead_high}) >= 2
