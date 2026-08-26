"""Proactive search across alerts, cases, IOCs, and threat intel for a given indicator."""
from .hunter import ThreatHunter
__all__ = ["ThreatHunter"]
