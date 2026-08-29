"""Structured JSON logging for AHRAS production deployments."""
import json, logging, os, sys, traceback
from datetime import datetime, timezone

class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": "ahras",
            "pid": os.getpid(),
        }
        if hasattr(record, "event"):
            payload["event"] = record.event
        if hasattr(record, "request_id"):
            payload["request_id"] = record.request_id
        if record.exc_info:
            payload["exception"] = "".join(traceback.format_exception(*record.exc_info))
        return json.dumps(payload, ensure_ascii=False, default=str)

def configure_json_logging(level=None):
    level = level or os.getenv("LOG_LEVEL", "INFO")
    root = logging.getLogger()
    root.setLevel(level.upper())
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.handlers.clear()
    root.addHandler(handler)
    return root
