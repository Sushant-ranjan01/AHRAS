"""AHRAS — Unified Configuration"""
import logging
import os
import secrets
import warnings
from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger("ahras.config")

_INSECURE_DEFAULT_SECRET = "ahras-super-secret-key-change-in-production"


def _resolve_secret_key() -> str:
    """
    Never silently run with the shipped placeholder SECRET_KEY. If SECRET_KEY
    isn't set in the environment:
      - in DEBUG mode: auto-generate a random one for this process (sessions/
        JWTs just won't survive a restart) and warn loudly.
      - outside DEBUG (i.e. production): refuse to start at all, so nobody
        accidentally deploys with a well-known key that lets anyone forge a
        valid JWT.
    """
    env_key = os.getenv("SECRET_KEY")
    debug = os.getenv("DEBUG", "true").lower() == "true"
    if env_key and env_key != _INSECURE_DEFAULT_SECRET:
        return env_key
    if not debug:
        raise RuntimeError(
            "SECRET_KEY is not set (or is still the default placeholder) while "
            "DEBUG=false. Refusing to start with an insecure/predictable JWT "
            "signing key in production. Set a real SECRET_KEY, e.g.:\n"
            "  python -c \"import secrets; print(secrets.token_hex(32))\""
        )
    generated = secrets.token_hex(32)
    warnings.warn(
        "SECRET_KEY not set — using a random key generated for this run only "
        "(all sessions/JWTs will be invalidated on restart). Set SECRET_KEY "
        "in your .env before deploying.",
        RuntimeWarning,
    )
    return generated


class Config:
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    MONGO_DB: str = os.getenv("MONGO_DB", "AHRAS_DB")
    SECRET_KEY: str = _resolve_secret_key()
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 480))
    NETWORK_INTERFACE: str = os.getenv("NETWORK_INTERFACE", "")
    SYNTHETIC_FALLBACK_ENABLED: bool = os.getenv("SYNTHETIC_FALLBACK_ENABLED", "false").lower() == "true"
    PORT_SCAN_THRESHOLD: int = int(os.getenv("PORT_SCAN_THRESHOLD", 20))
    FLOOD_THRESHOLD: int = int(os.getenv("FLOOD_THRESHOLD", 500))
    SSH_BRUTEFORCE_THRESHOLD: int = int(os.getenv("SSH_BRUTEFORCE_THRESHOLD", 10))
    RISK_WINDOW_SECONDS: int = int(os.getenv("RISK_WINDOW_SECONDS", 60))
    TRUST_IP_WHITELIST: list = os.getenv("TRUST_IP_WHITELIST", "127.0.0.1,10.0.1.138").split(",")
    MODEL_PATH: str = os.getenv("MODEL_PATH", "models/anomaly_model.pkl")
    TRAIN_SAMPLES: int = int(os.getenv("TRAIN_SAMPLES", 1000))
    CONTAMINATION: float = float(os.getenv("CONTAMINATION", 0.05))
    # Labeled CICIDS-style CSV (e.g. Bot.csv) used to build the anomaly
    # model's baseline from real benign flows instead of synthetic data.
    # Required for the anomaly_score calibration to generalize -- see
    # detection/anomaly_engine/train_model.py::_real_benign(). Empty string
    # falls back to the synthetic baseline (train_model.py logs a warning).
    TRAIN_BASELINE_CSV: str = os.getenv("TRAIN_BASELINE_CSV", "")
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", 8000))
    DEBUG: bool = os.getenv("DEBUG", "true").lower() == "true"
    FIREWALL_ENABLED: bool = os.getenv("FIREWALL_ENABLED", "false").lower() == "true"
    AUTO_BLOCK_ENABLED: bool = os.getenv("AUTO_BLOCK_ENABLED", "false").lower() == "true"
    AUTO_BLOCK_RISK_THRESHOLD: float = float(os.getenv("AUTO_BLOCK_RISK_THRESHOLD", 9.0))
    PORT_CONTROL_ENABLED: bool = os.getenv("PORT_CONTROL_ENABLED", "false").lower() == "true"
    LOW_RISK_MAX: float = 3.0
    MEDIUM_RISK_MAX: float = 6.0
    HIGH_RISK_MAX: float = 8.5

    @classmethod
    def severity_from_risk(cls, risk: float) -> str:
        if risk <= cls.LOW_RISK_MAX: return "LOW"
        elif risk <= cls.MEDIUM_RISK_MAX: return "MEDIUM"
        elif risk <= cls.HIGH_RISK_MAX: return "HIGH"
        return "CRITICAL"

config = Config()