"""
AHRAS v4 -- Temporal Attack Prediction  (Phase 1 -- Research Contribution)
==========================================================================
Problem: AHRAS reacts to attacks as they happen. It has no forward-looking
view -- an analyst can't tell "is this IP escalating?" without manually
reading the event history.

Solution: per-indicator time-series forecasting on the risk_score sequence
already stored in historical_risk.IndicatorHistory.recent_events.

Method: Holt's Linear (double exponential smoothing) -- level + trend.
Chosen over ARIMA/LSTM because:
  - No external deps beyond numpy (already required)
  - Works with short, sparse, irregularly-spaced series (typical for
    security events -- an IP might have 3 events today, 0 tomorrow)
  - Fully interpretable: level = current risk baseline,
    trend = rate of escalation/de-escalation
  - Fast enough to run on-demand for any indicator in < 1ms

Formula (Holt's method):
  level_t = alpha * y_t + (1-alpha) * (level_{t-1} + trend_{t-1})
  trend_t = beta  * (level_t - level_{t-1}) + (1-beta) * trend_{t-1}
  forecast(h) = level_t + h * trend_t

Output: a forecast for the next N "ticks" (next events), a trend label
(ESCALATING / STABLE / DE-ESCALATING), and a confidence score based on
how much historical data and variance there is.
"""
import logging
import math
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger("ahras.forecast")

ALPHA = 0.5     # level smoothing factor
BETA  = 0.3     # trend smoothing factor
MIN_POINTS_FOR_FORECAST = 3
ESCALATION_THRESHOLD = 2.0   # trend pts/event to call it "escalating"
DEFAULT_CRITICAL_THRESHOLD = 85.0   # matches risk_scorer.py's CRITICAL cutoff


@dataclass
class ForecastResult:
    indicator: str
    data_points: int
    current_level: float
    trend: float                     # points per event
    trend_label: str                 # ESCALATING | STABLE | DE-ESCALATING
    forecast_next: List[float]       # predicted risk scores for next N events
    confidence: float                # 0-1, based on data volume + consistency
    will_breach_critical: bool       # will forecast cross 85 within horizon?
    breach_in_events: Optional[int]  # how many events until breach, if any

    def to_dict(self) -> dict:
        return {
            "indicator": self.indicator,
            "data_points": self.data_points,
            "current_level": round(self.current_level, 1),
            "trend": round(self.trend, 2),
            "trend_label": self.trend_label,
            "forecast_next": [round(v, 1) for v in self.forecast_next],
            "confidence": round(self.confidence, 2),
            "will_breach_critical": self.will_breach_critical,
            "breach_in_events": self.breach_in_events,
        }


class AttackPredictor:
    """
    Stateless predictor -- operates on whatever risk-score sequence is
    handed to it (typically IndicatorHistory.recent_events from
    historical_risk.engine). No persistence of its own; it is cheap
    enough to recompute on every request.
    """

    def __init__(self, horizon: int = 5):
        self.horizon = horizon   # how many future events to forecast

    def predict(self, indicator: str, risk_history: List[float]) -> ForecastResult:
        """
        risk_history: chronological list of past risk_score_100 values
        for one indicator (oldest first).
        """
        n = len(risk_history)
        if n < MIN_POINTS_FOR_FORECAST:
            return ForecastResult(
                indicator=indicator, data_points=n,
                current_level=risk_history[-1] if risk_history else 0.0,
                trend=0.0, trend_label="INSUFFICIENT_DATA", forecast_next=[],
                confidence=0.0, will_breach_critical=False, breach_in_events=None,
            )

        level, trend = self._holt_fit(risk_history)

        forecast = []
        for h in range(1, self.horizon + 1):
            val = max(0.0, min(100.0, level + h * trend))
            forecast.append(val)

        if trend > ESCALATION_THRESHOLD:
            label = "ESCALATING"
        elif trend < -ESCALATION_THRESHOLD:
            label = "DE-ESCALATING"
        else:
            label = "STABLE"

        variance = self._variance(risk_history)
        data_confidence = min(1.0, n / 20.0)
        stability_confidence = max(0.0, 1.0 - variance / 2500.0)
        confidence = round(0.6 * data_confidence + 0.4 * stability_confidence, 3)

        breach_idx = None
        for i, v in enumerate(forecast):
            if v >= 85.0:
                breach_idx = i + 1
                break

        return ForecastResult(
            indicator=indicator, data_points=n, current_level=level, trend=trend,
            trend_label=label, forecast_next=forecast, confidence=confidence,
            will_breach_critical=breach_idx is not None, breach_in_events=breach_idx,
        )

    def predict_from_events(self, indicator: str, recent_events: List[dict]) -> ForecastResult:
        """Convenience wrapper -- extracts risk_score from
        historical_risk.IndicatorHistory.recent_events snapshot dicts."""
        scores = [e.get("risk_score", 0.0) for e in recent_events if "risk_score" in e]
        return self.predict(indicator, scores)

    # -- Internals ----------------------------------------------------------
    def _holt_fit(self, series: List[float]) -> Tuple[float, float]:
        level = series[0]
        trend = series[1] - series[0] if len(series) > 1 else 0.0
        for y in series[1:]:
            prev_level = level
            level = ALPHA * y + (1 - ALPHA) * (level + trend)
            trend = BETA * (level - prev_level) + (1 - BETA) * trend
        return level, trend

    def _variance(self, series: List[float]) -> float:
        if len(series) < 2:
            return 0.0
        mean = sum(series) / len(series)
        return sum((x - mean) ** 2 for x in series) / len(series)

    # -- Batch / fleet-wide forecasting --------------------------------------
    def predict_fleet(self, indicator_histories: Dict[str, List[float]]) -> List[ForecastResult]:
        """Run prediction across many indicators at once -- used by the
        /api/forecast/escalating endpoint to surface the riskiest trending IPs."""
        results = []
        for indicator, history in indicator_histories.items():
            try:
                results.append(self.predict(indicator, history))
            except Exception as e:
                logger.warning(f"Forecast failed for {indicator}: {e}")
        return results

    def top_escalating(self, indicator_histories: Dict[str, List[float]], n: int = 10) -> List[ForecastResult]:
        """Returns the N indicators with the strongest positive trend --
        i.e. the ones an analyst should look at NEXT, before they peak."""
        results = self.predict_fleet(indicator_histories)
        escalating = [r for r in results if r.trend_label == "ESCALATING"]
        escalating.sort(key=lambda r: r.trend, reverse=True)
        return escalating[:n]


# ─────────────────────────────────────────────────────────────────────────
# Forecast evaluation -- accuracy (MAE/RMSE) and early-warning lead time
# ─────────────────────────────────────────────────────────────────────────
# These were the two outstanding review items for the forecasting module:
# the predictor's docstring claims "fully interpretable" one-step-ahead
# forecasts and (via ForecastResult.will_breach_critical) an early-warning
# capability, but neither claim had ever actually been measured against a
# real risk-score series. Both functions below are CAUSAL/walk-forward by
# construction: at "time" t they only ever call predict() with
# series[:t] (everything strictly BEFORE t), then score that forecast
# against series[t] -- the predictor never sees the value it's being
# judged against. This mirrors how the forecaster is actually used in
# production (predict on history-so-far, find out what really happened
# next) and rules out any lookahead leakage in the reported numbers.

def walk_forward_errors(predictor: "AttackPredictor", series: List[float],
                         min_points: int = MIN_POINTS_FOR_FORECAST) -> List[float]:
    """
    One-step-ahead forecast error at every point in `series` where enough
    history exists to forecast at all. error = forecast_next[0] - actual.
    Signed (not absolute) so callers can also inspect systematic bias
    (e.g. a forecaster that's consistently late to react to escalation
    would show a persistent positive error during ramp-up).
    """
    errors: List[float] = []
    for t in range(min_points, len(series)):
        history = series[:t]
        actual = series[t]
        result = predictor.predict("__walk_forward_eval__", history)
        if not result.forecast_next:
            continue
        one_step_ahead = result.forecast_next[0]
        errors.append(one_step_ahead - actual)
    return errors


def forecast_accuracy(predictor: "AttackPredictor", series: List[float],
                       min_points: int = MIN_POINTS_FOR_FORECAST) -> Dict[str, float]:
    """
    Walk-forward one-step-ahead MAE and RMSE for a single risk-score
    series. Returns n=0, mae=0.0, rmse=0.0 if there isn't enough history
    to produce even one causal forecast (rather than raising), since
    short/new indicators are a normal, expected case in production.
    """
    errors = walk_forward_errors(predictor, series, min_points=min_points)
    if not errors:
        return {"n": 0, "mae": 0.0, "rmse": 0.0}
    mae = sum(abs(e) for e in errors) / len(errors)
    rmse = math.sqrt(sum(e * e for e in errors) / len(errors))
    return {"n": len(errors), "mae": round(mae, 3), "rmse": round(rmse, 3)}


def threshold_crossing_lead_time(predictor: "AttackPredictor", series: List[float],
                                  threshold: float = DEFAULT_CRITICAL_THRESHOLD,
                                  min_points: int = MIN_POINTS_FOR_FORECAST) -> Optional[int]:
    """
    How many events BEFORE the real score actually crosses `threshold`
    did the forecaster first raise a warning (will_breach_critical=True)?

    Walks forward causally: for every t_pred from min_points up to (but
    not including) the actual crossing event t_actual, calls
    predict(series[:t_pred]) and checks whether its forecast_next ever
    reaches `threshold` within the horizon. Returns the lead time
    (t_actual - t_pred) for the FIRST t_pred that warned -- i.e. the
    earliest, most useful warning the forecaster actually gave, using
    only information available at that point in time.

    NOTE: this checks forecast_next against `threshold` directly rather
    than ForecastResult.will_breach_critical, because that flag is
    hardcoded to CRITICAL (85) inside predict() -- it would silently
    ignore a caller-supplied threshold and either over- or under-report
    lead time for any threshold != 85.

    Returns None if:
      - the series never actually crosses `threshold` (nothing to time), or
      - it crosses before min_points of history even exist (no forecast
        was possible in time to warn), or
      - no causal forecast ever fired a warning before the real crossing
        (a genuine miss -- worth reporting as None/no-coverage, not
        silently excluding it from the caller's stats).
    """
    t_actual = next((i for i, v in enumerate(series) if v >= threshold), None)
    if t_actual is None or t_actual < min_points:
        return None

    for t_pred in range(min_points, t_actual):
        result = predictor.predict("__lead_time_eval__", series[:t_pred])
        if any(v >= threshold for v in result.forecast_next):
            return t_actual - t_pred
    return None  # never warned in time -- a miss, distinct from "no crossing"
