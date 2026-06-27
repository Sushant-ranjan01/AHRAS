"""AHRAS — Unified Configuration"""
import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    MONGO_DB: str = os.getenv("MONGO_DB", "AHRAS_DB")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "ahras-super-secret-key-change-in-production")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 480))
    NETWORK_INTERFACE: str = os.getenv("NETWORK_INTERFACE", "")
    PORT_SCAN_THRESHOLD: int = int(os.getenv("PORT_SCAN_THRESHOLD", 20))
    FLOOD_THRESHOLD: int = int(os.getenv("FLOOD_THRESHOLD", 500))
    SSH_BRUTEFORCE_THRESHOLD: int = int(os.getenv("SSH_BRUTEFORCE_THRESHOLD", 10))
    RISK_WINDOW_SECONDS: int = int(os.getenv("RISK_WINDOW_SECONDS", 60))
    TRUST_IP_WHITELIST: list = os.getenv("TRUST_IP_WHITELIST", "127.0.0.1,10.0.1.138").split(",")
    MODEL_PATH: str = os.getenv("MODEL_PATH", "models/anomaly_model.pkl")
    TRAIN_SAMPLES: int = int(os.getenv("TRAIN_SAMPLES", 1000))
    CONTAMINATION: float = float(os.getenv("CONTAMINATION", 0.05))
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
