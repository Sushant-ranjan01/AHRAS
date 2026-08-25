"""Detects ransomware-like behavior (rapid file encryption patterns)."""
from .detector import RansomwareDetector, RansomwareAlert
__all__ = ["RansomwareDetector", "RansomwareAlert"]
