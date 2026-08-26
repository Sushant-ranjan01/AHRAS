"""Links related alerts/events together into a single incident narrative."""
from .engine import CorrelationEngine, CorrelatedIncident
__all__ = ["CorrelationEngine", "CorrelatedIncident"]
