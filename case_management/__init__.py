"""Tracks investigation cases: creation, status, notes, linked alerts."""
from .manager import CaseManager, Case, CaseStatus
__all__ = ["CaseManager", "Case", "CaseStatus"]
