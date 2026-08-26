"""
AHRAS v7 — MongoDB Connection Manager
======================================
Central connection handler for all MongoDB operations.

Features:
  - Singleton pattern — one client shared across all modules
  - Auto-reconnect on connection loss
  - Graceful fallback to in-memory mode if MongoDB is unavailable
  - Connection health check endpoint
  - Index creation on startup for performance
  - TTL indexes for automatic data expiry (old events, alerts)

Collections used by AHRAS:
  events          — all network events (TTL: 30 days)
  alerts          — analyst alerts (TTL: 90 days)
  cases           — investigation cases (permanent)
  iocs            — indicators of compromise (permanent)
  forensics       — forensic cases with evidence/timeline/notes
  threat_intel    — TI lookup cache (TTL: 1 hour)
  historical_risk — indicator history (permanent)
  users           — user accounts (permanent)
  uba_profiles    — UBA baseline profiles (permanent)
  soar_logs       — SOAR playbook execution logs (TTL: 30 days)
  honeypot_hits   — honeypot interactions (TTL: 7 days)
  normalizer_logs — normalised log entries (TTL: 7 days)
"""

import logging
import threading
import time
from typing import Optional

from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import (
    ConnectionFailure, ServerSelectionTimeoutError, ConfigurationError
)

logger = logging.getLogger("ahras.database")

# ── Singleton state ───────────────────────────────────────────────────────────
_client:   Optional[MongoClient] = None
_db:       Optional[Database]    = None
_lock      = threading.Lock()
_connected = False
_fallback  = False   # True when running in memory-only mode


def connect(uri: str = "mongodb://localhost:27017",
            db_name: str = "ahras_db",
            timeout_ms: int = 3000) -> bool:
    """
    Connect to MongoDB. Returns True on success, False on failure.
    On failure, AHRAS continues with in-memory storage (graceful fallback).
    """
    global _client, _db, _connected, _fallback

    with _lock:
        try:
            logger.info(f"Connecting to MongoDB: {uri} / {db_name}")
            client = MongoClient(
                uri,
                serverSelectionTimeoutMS=timeout_ms,
                connectTimeoutMS=timeout_ms,
                socketTimeoutMS=timeout_ms * 2,
            )
            # Force a real connection test
            client.admin.command("ping")
            _client    = client
            _db        = client[db_name]
            _connected = True
            _fallback  = False
            logger.info(f"MongoDB connected — database: {db_name}")
            _create_indexes()
            return True

        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.warning(
                f"MongoDB unavailable ({e}). "
                f"AHRAS will run with in-memory storage. "
                f"Start MongoDB and restart to enable persistence."
            )
            _connected = False
            _fallback  = True
            return False

        except ConfigurationError as e:
            logger.error(f"MongoDB configuration error: {e}")
            _connected = False
            _fallback  = True
            return False


def get_db() -> Optional[Database]:
    """Return the connected database, or None if in fallback mode."""
    return _db if _connected else None


def get_collection(name: str) -> Optional[Collection]:
    """Return a collection handle, or None if in fallback mode."""
    if _connected and _db is not None:
        return _db[name]
    return None


def is_connected() -> bool:
    return _connected


def is_fallback() -> bool:
    return _fallback


def health() -> dict:
    """Return MongoDB health status for the /health endpoint."""
    if not _connected:
        return {
            "status": "disconnected",
            "mode": "in-memory (fallback)",
            "note": "Data will not persist across restarts. Start MongoDB to enable persistence.",
        }
    try:
        _db.command("ping")
        stats = _db.command("dbStats")
        return {
            "status": "connected",
            "mode": "mongodb",
            "database": _db.name,
            "collections": stats.get("collections", 0),
            "data_size_mb": round(stats.get("dataSize", 0) / 1_048_576, 2),
            "storage_size_mb": round(stats.get("storageSize", 0) / 1_048_576, 2),
            "indexes": stats.get("indexes", 0),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def disconnect():
    """Cleanly close the MongoDB connection."""
    global _client, _db, _connected
    with _lock:
        if _client:
            _client.close()
            _client    = None
            _db        = None
            _connected = False
            logger.info("MongoDB disconnected")


# ── Index setup ───────────────────────────────────────────────────────────────

def _create_indexes():
    """Create all required indexes. Called once on connect."""
    if _db is None:
        return

    try:
        # events — sorted by timestamp desc, TTL 30 days
        _db.events.create_index([("timestamp", DESCENDING)])
        _db.events.create_index([("src_ip", ASCENDING)])
        _db.events.create_index([("attack_type", ASCENDING)])
        _db.events.create_index([("severity", ASCENDING)])
        _db.events.create_index(
            [("created_at", ASCENDING)],
            expireAfterSeconds=30 * 86400,  # 30 days
            name="events_ttl"
        )

        # alerts
        _db.alerts.create_index([("created_at", DESCENDING)])
        _db.alerts.create_index([("src_ip", ASCENDING)])
        _db.alerts.create_index([("severity", ASCENDING)])
        _db.alerts.create_index([("status", ASCENDING)])
        _db.alerts.create_index([("alert_id", ASCENDING)], unique=True)
        _db.alerts.create_index(
            [("created_at_dt", ASCENDING)],
            expireAfterSeconds=90 * 86400,  # 90 days
            name="alerts_ttl"
        )

        # cases
        _db.cases.create_index([("case_id", ASCENDING)], unique=True)
        _db.cases.create_index([("status", ASCENDING)])
        _db.cases.create_index([("created_at", DESCENDING)])
        _db.cases.create_index([("src_ip", ASCENDING)])

        # iocs
        _db.iocs.create_index([("indicator", ASCENDING)], unique=True)
        _db.iocs.create_index([("ioc_type", ASCENDING)])
        _db.iocs.create_index([("threat_level", ASCENDING)])
        _db.iocs.create_index([("active", ASCENDING)])

        # forensics
        _db.forensics.create_index([("case_id", ASCENDING)], unique=True)
        _db.forensics.create_index([("analyst", ASCENDING)])
        _db.forensics.create_index([("status", ASCENDING)])

        # threat_intel cache — TTL 1 hour
        _db.threat_intel.create_index([("indicator", ASCENDING)], unique=True)
        _db.threat_intel.create_index(
            [("cached_at", ASCENDING)],
            expireAfterSeconds=3600,  # 1 hour
            name="ti_cache_ttl"
        )

        # historical_risk
        _db.historical_risk.create_index(
            [("indicator", ASCENDING), ("indicator_type", ASCENDING)],
            unique=True, name="indicator_unique"
        )
        _db.historical_risk.create_index([("incident_count", DESCENDING)])
        _db.historical_risk.create_index([("last_seen", DESCENDING)])

        # users
        _db.users.create_index([("username", ASCENDING)], unique=True)

        # uba_profiles
        _db.uba_profiles.create_index([("src_ip", ASCENDING)], unique=True)

        # soar_logs — TTL 30 days
        _db.soar_logs.create_index([("timestamp", DESCENDING)])
        _db.soar_logs.create_index(
            [("timestamp_dt", ASCENDING)],
            expireAfterSeconds=30 * 86400,
            name="soar_logs_ttl"
        )

        # honeypot_hits — TTL 7 days
        _db.honeypot_hits.create_index([("timestamp", DESCENDING)])
        _db.honeypot_hits.create_index([("src_ip", ASCENDING)])
        _db.honeypot_hits.create_index(
            [("timestamp_dt", ASCENDING)],
            expireAfterSeconds=7 * 86400,
            name="honeypot_ttl"
        )

        # normalizer_logs — TTL 7 days
        _db.normalizer_logs.create_index([("timestamp", DESCENDING)])
        _db.normalizer_logs.create_index(
            [("indexed_at", ASCENDING)],
            expireAfterSeconds=7 * 86400,
            name="normalizer_ttl"
        )

        logger.info("MongoDB indexes created successfully")

    except Exception as e:
        logger.warning(f"Index creation warning: {e}")
