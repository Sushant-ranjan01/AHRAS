"""
AHRAS v4 -- pytest conftest.py
Shared fixtures used across the entire test suite.
"""
import os
import sys
import pytest

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


@pytest.fixture(scope="session")
def risk_engine():
    from risk_engine.risk_scorer import RiskEngine
    eng = RiskEngine()
    return eng


@pytest.fixture(scope="session")
def risk_explainer(risk_engine):
    from risk_explainer import RiskExplainer
    return RiskExplainer()


@pytest.fixture(scope="session")
def xai_explainer():
    from xai import ExtendedExplainer
    return ExtendedExplainer()


@pytest.fixture(scope="session")
def weight_learner():
    from adaptive_learning.weight_learner import AdaptiveWeightLearner
    return AdaptiveWeightLearner(mongo_collection=None)


@pytest.fixture(scope="session")
def predictor():
    from forecast.predictor import AttackPredictor
    return AttackPredictor(horizon=5)


@pytest.fixture(scope="session")
def threat_graph():
    from graph.engine import ThreatGraph
    return ThreatGraph()


@pytest.fixture(scope="session")
def metrics_calc():
    from evaluation.metrics import MetricsCalculator
    return MetricsCalculator()


@pytest.fixture
def sample_det_external():
    """A clearly malicious external attacker detection dict."""
    return {
        "src_ip": "45.33.32.156",
        "attack_type": "Port Scan",
        "confidence": 0.9,
        "packet_count": 80,
        "unique_ports": 25,
        "syn_count": 40,
        "pps": 150,
        "anomaly_flag": True,
    }


@pytest.fixture
def sample_det_benign():
    """Benign local traffic."""
    return {
        "src_ip": "192.168.29.1",
        "attack_type": "Normal",
        "confidence": 0.1,
        "packet_count": 5,
        "anomaly_flag": False,
    }


@pytest.fixture
def sample_explanation():
    """Pre-built explanation dict mimicking RiskExplanation.to_dict()."""
    return {
        "src_ip": "45.33.32.156",
        "final_score": 92.0,
        "severity": "CRITICAL",
        "components": [
            {"name": "threat_intel", "label": "Threat Intelligence",
             "raw_value": 0.95, "weight": 30, "contribution": 28.5},
            {"name": "asset", "label": "Asset Criticality",
             "raw_value": 0.8, "weight": 20, "contribution": 16.0},
            {"name": "mitre", "label": "MITRE ATT&CK",
             "raw_value": 1.0, "weight": 20, "contribution": 20.0},
            {"name": "uba", "label": "UBA",
             "raw_value": 0.6, "weight": 15, "contribution": 9.0},
            {"name": "ml_anomaly", "label": "ML Anomaly",
             "raw_value": 1.0, "weight": 15, "contribution": 15.0},
        ],
    }
