"""Remembers past incidents per indicator so repeat offenders score higher over time."""
from .engine import HistoricalRiskEngine, IndicatorHistory
__all__ = ["HistoricalRiskEngine", "IndicatorHistory"]
