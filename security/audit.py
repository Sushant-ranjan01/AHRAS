"""Security audit trail. Writes to MongoDB when available and always logs locally."""
import logging, time
from database import get_collection

logger = logging.getLogger("ahras.security.audit")

def record(action, actor="system", ip="unknown", resource="", outcome="success", details=None):
    event = {
        "timestamp": time.time(), "action": action, "actor": actor, "ip": ip,
        "resource": resource, "outcome": outcome, "details": details or {},
    }
    logger.info("AUDIT %s", event)
    try:
        col = get_collection("audit_logs")
        if col is not None:
            col.insert_one(event)
    except Exception as exc:
        logger.warning("Could not persist audit event: %s", exc)
    return event
