"""Fail-fast production startup validation."""
import os
import sys
from config import config
from database import db_health

if not config.DEBUG:
    if not config.SECRET_KEY or len(config.SECRET_KEY) < 32 or "change-this" in config.SECRET_KEY.lower():
        raise SystemExit("Production startup refused: SECRET_KEY must be a strong random value (32+ chars).")
    origins = os.getenv("ALLOWED_ORIGINS", "").strip()
    if not origins:
        raise SystemExit("Production startup refused: ALLOWED_ORIGINS must be configured.")

health = db_health()
print(f"AHRAS startup: debug={config.DEBUG}, mongodb={health.get('status')}")
