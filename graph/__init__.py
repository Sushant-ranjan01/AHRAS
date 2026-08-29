"""Builds an entity relationship graph (IPs, users, assets) for correlation and pivoting."""
from .engine import ThreatGraph

__all__ = ["ThreatGraph"]
