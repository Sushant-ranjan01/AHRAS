"""Loads benchmark datasets and scores detection accuracy (precision/recall/F1)."""
from .dataset_loader import DatasetLoader
from .metrics import MetricsCalculator
from .runner import EvaluationRunner

__all__ = ["DatasetLoader", "MetricsCalculator", "EvaluationRunner"]
