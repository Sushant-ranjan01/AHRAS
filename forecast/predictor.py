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
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger("ahras.forecast")

ALPHA = 0.5     # level smoothing factor
BETA  = 0.3     # trend smoothing factor
MIN_POINTS_FOR_FORECAST = 3
ESCALATION_THRESHOLD = 2.0   # trend pts/event to call it "escalating"


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
