"""
AHRAS v7 — MongoDB Repositories
=================================
One repository class per collection. Each extends MongoRepository
so it gets free CRUD + fallback. Specialised query methods are added
per collection where needed.
"""

import time
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict

from .repository import MongoRepository
from .connection import get_collection

logger = logging.getLogger("ahras.database.repos")


class EventRepository(MongoRepository):
    """Stores all network events detected by AHRAS."""
    COLLECTION = "events"
    ID_FIELD   = "event_id"

    def recent(self, n: int = 100) -> List[dict]:
        return self.find_many(sort_field="timestamp", sort_desc=True, limit=n)

    def by_ip(self, ip: str, limit: int = 50) -> List[dict]:
        return self.find_many({"src_ip": ip}, sort_field="timestamp",
                              sort_desc=True, limit=limit)

    def by_attack_type(self, attack_type: str, limit: int = 50) -> List[dict]:
        return self.find_many({"attack_type": attack_type},
                              sort_field="timestamp", sort_desc=True, limit=limit)

    def severity_counts(self) -> Dict[str, int]:
        return self.group_count("severity")

    def attack_type_counts(self) -> Dict[str, int]:
        return self.group_count("attack_type")

    def total_count(self) -> int:
        return self.count()

    def search(self, query: str, limit: int = 50) -> List[dict]:
        """Text search across src_ip and attack_type."""
        col = get_collection(self.COLLECTION)
        if col is not None:
            try:
                results = list(col.find(
                    {"$or": [
                        {"src_ip": {"$regex": query, "$options": "i"}},
                        {"attack_type": {"$regex": query, "$options": "i"}},
                    ]},
                    {"_id": 0}
                ).sort("timestamp", -1).limit(limit))
                return results
            except Exception as e:
                logger.error(f"Event search error: {e}")
        # Memory fallback
        q = query.lower()
        return [v for v in list(self._memory.values())[-500:]
                if q in str(v.get("src_ip", "")).lower()
                or q in str(v.get("attack_type", "")).lower()][:limit]


class AlertRepository(MongoRepository):
    """Stores analyst alerts with full lifecycle (pending → ack → closed)."""
    COLLECTION = "alerts"
    ID_FIELD   = "alert_id"

    def pending(self, limit: int = 50) -> List[dict]:
        return self.find_many({"status": "PENDING"},
                              sort_field="created_at", sort_desc=True, limit=limit)

    def by_severity(self, severity: str, limit: int = 50) -> List[dict]:
        return self.find_many({"severity": severity.upper()},
                              sort_field="created_at", sort_desc=True, limit=limit)

    def by_ip(self, ip: str, limit: int = 50) -> List[dict]:
        return self.find_many({"src_ip": ip},
                              sort_field="created_at", sort_desc=True, limit=limit)

    def recent(self, limit: int = 50) -> List[dict]:
        return self.find_many(sort_field="created_at", sort_desc=True, limit=limit)

    def severity_counts(self) -> Dict[str, int]:
        return self.group_count("severity")

    def status_counts(self) -> Dict[str, int]:
        return self.group_count("status")


class CaseRepository(MongoRepository):
    """Stores investigation cases."""
    COLLECTION = "cases"
    ID_FIELD   = "case_id"

    def open_cases(self, limit: int = 50) -> List[dict]:
        return self.find_many({"status": "OPEN"},
                              sort_field="created_at", sort_desc=True, limit=limit)

    def by_priority(self, priority: str, limit: int = 50) -> List[dict]:
        return self.find_many({"priority": priority.upper()},
                              sort_field="created_at", sort_desc=True, limit=limit)

    def by_ip(self, ip: str, limit: int = 20) -> List[dict]:
        return self.find_many({"src_ip": ip},
                              sort_field="created_at", sort_desc=True, limit=limit)

    def status_counts(self) -> Dict[str, int]:
        return self.group_count("status")


class IOCRepository(MongoRepository):
    """Stores Indicators of Compromise."""
    COLLECTION = "iocs"
    ID_FIELD   = "ioc_id"

    def save(self, doc: dict) -> bool:
        """
        Upsert by `indicator` (the unique-indexed field) rather than ioc_id.
        This prevents E11000 duplicate key errors when the same indicator is
        saved again with a different ioc_id.
        """
        doc = self._stamp(dict(doc))
        indicator = doc.get("indicator")
        if not indicator:
            return super().save(doc)
        # Keep in memory keyed by ioc_id for fast local reads
        key = doc.get(self.ID_FIELD)
        if key:
            self._memory[key] = doc
        col = self._col
        if col is not None:
            try:
                col.update_one(
                    {"indicator": indicator},
                    {"$set": doc},
                    upsert=True
                )
                return True
            except Exception as e:
                logger.error(f"MongoDB save error [{self._col_name}]: {e}")
        return True  # already in memory

    def by_indicator(self, indicator: str) -> Optional[dict]:
        """Exact match on indicator string."""
        # Check memory first
        for v in self._memory.values():
            if v.get("indicator") == indicator:
                return dict(v)
        col = get_collection(self.COLLECTION)
        if col is not None:
            try:
                doc = col.find_one({"indicator": indicator}, {"_id": 0})
                return doc
            except Exception as e:
                logger.error(f"IOC by_indicator error: {e}")
        return None

    def active(self, ioc_type: str = None, limit: int = 500) -> List[dict]:
        query: dict = {"active": True}
        if ioc_type:
            query["ioc_type"] = ioc_type
        return self.find_many(query, sort_field="created_at",
                              sort_desc=True, limit=limit)

    def by_threat_level(self, level: str, limit: int = 100) -> List[dict]:
        return self.find_many({"threat_level": level.upper(), "active": True},
                              sort_field="created_at", sort_desc=True, limit=limit)

    def type_counts(self) -> Dict[str, int]:
        return self.group_count("ioc_type")


class ForensicsRepository(MongoRepository):
    """Stores forensic cases with embedded evidence, timeline, and notes."""
    COLLECTION = "forensics"
    ID_FIELD   = "case_id"

    def open_cases(self) -> List[dict]:
        return self.find_many({"status": "OPEN"},
                              sort_field="created_at", sort_desc=True, limit=100)

    def by_analyst(self, analyst: str, limit: int = 20) -> List[dict]:
        return self.find_many({"analyst": analyst},
                              sort_field="created_at", sort_desc=True, limit=limit)

    def add_evidence_item(self, case_id: str, ev_dict: dict) -> bool:
        """Append a single evidence item to the embedded evidence array."""
        col = get_collection(self.COLLECTION)
        if col is not None:
            try:
                col.update_one(
                    {self.ID_FIELD: case_id},
                    {"$push": {"evidence": ev_dict}}
                )
                # Update memory cache
                if case_id in self._memory:
                    self._memory[case_id].setdefault("evidence", []).append(ev_dict)
                return True
            except Exception as e:
                logger.error(f"ForensicsRepo add_evidence error: {e}")
        # Fallback
        if case_id in self._memory:
            self._memory[case_id].setdefault("evidence", []).append(ev_dict)
            return True
        return False

    def add_timeline_event(self, case_id: str, event_dict: dict) -> bool:
        """Append a timeline event to the embedded timeline array."""
        col = get_collection(self.COLLECTION)
        if col is not None:
            try:
                col.update_one(
                    {self.ID_FIELD: case_id},
                    {"$push": {"timeline": event_dict}}
                )
                if case_id in self._memory:
                    self._memory[case_id].setdefault("timeline", []).append(event_dict)
                return True
            except Exception as e:
                logger.error(f"ForensicsRepo add_timeline error: {e}")
        if case_id in self._memory:
            self._memory[case_id].setdefault("timeline", []).append(event_dict)
            return True
        return False

    def add_note(self, case_id: str, note_dict: dict) -> bool:
        """Append a note to the embedded notes array."""
        col = get_collection(self.COLLECTION)
        if col is not None:
            try:
                col.update_one(
                    {self.ID_FIELD: case_id},
                    {"$push": {"notes": note_dict}}
                )
                if case_id in self._memory:
                    self._memory[case_id].setdefault("notes", []).append(note_dict)
                return True
            except Exception as e:
                logger.error(f"ForensicsRepo add_note error: {e}")
        if case_id in self._memory:
            self._memory[case_id].setdefault("notes", []).append(note_dict)
            return True
        return False


class ThreatIntelCacheRepository(MongoRepository):
    """
    Caches TI API results keyed by indicator.
    TTL index on cached_at automatically expires entries after 1 hour.
    """
    COLLECTION = "threat_intel"
    ID_FIELD   = "indicator"

    def get_cached(self, indicator: str) -> Optional[dict]:
        """Return cached TI result or None if expired/missing."""
        # Memory check first
        cached = self._memory.get(indicator)
        if cached:
            age = time.time() - cached.get("cached_at_ts", 0)
            if age < 3600:
                return cached
            else:
                self._memory.pop(indicator, None)
        # MongoDB check (TTL index handles expiry automatically)
        return self.find_by_id(indicator)

    def cache(self, indicator: str, result: dict):
        """Store a TI result in the cache."""
        doc = dict(result)
        doc["indicator"]    = indicator
        doc["cached_at_ts"] = time.time()
        doc["cached_at"]    = datetime.now(timezone.utc)
        self.save(doc)


class HistoricalRiskRepository(MongoRepository):
    """Persists the HistoricalRiskEngine indicator store to MongoDB."""
    COLLECTION = "historical_risk"
    ID_FIELD   = "indicator_key"  # format: "ip:10.0.0.1"

    def top_by_boost(self, n: int = 20) -> List[dict]:
        return self.find_many(sort_field="history_boost",
                              sort_desc=True, limit=n)

    def top_by_incidents(self, n: int = 20) -> List[dict]:
        return self.find_many(sort_field="incident_count",
                              sort_desc=True, limit=n)

    def search(self, query: str, limit: int = 50) -> List[dict]:
        col = get_collection(self.COLLECTION)
        if col is not None:
            try:
                return list(col.find(
                    {"indicator": {"$regex": query, "$options": "i"}},
                    {"_id": 0}
                ).sort("history_boost", -1).limit(limit))
            except Exception as e:
                logger.error(f"HistoricalRisk search error: {e}")
        q = query.lower()
        return [v for v in self._memory.values()
                if q in str(v.get("indicator", "")).lower()][:limit]


class UserRepository(MongoRepository):
    """Stores user accounts. Only used by AuthManager."""
    COLLECTION = "users"
    ID_FIELD   = "username"

    def by_username(self, username: str) -> Optional[dict]:
        return self.find_by_id(username)

    def all_users(self) -> List[dict]:
        """Return all users without exposing password hashes."""
        docs = self.all()
        return [{k: v for k, v in d.items() if k != "hashed_password"}
                for d in docs]


class SOARLogRepository(MongoRepository):
    """Stores SOAR playbook execution logs."""
    COLLECTION = "soar_logs"
    ID_FIELD   = "log_id"

    def by_playbook(self, playbook: str, limit: int = 50) -> List[dict]:
        return self.find_many({"playbook": playbook},
                              sort_field="timestamp", sort_desc=True, limit=limit)

    def by_ip(self, ip: str, limit: int = 20) -> List[dict]:
        return self.find_many({"src_ip": ip},
                              sort_field="timestamp", sort_desc=True, limit=limit)


class HoneypotRepository(MongoRepository):
    """Stores honeypot interaction records."""
    COLLECTION = "honeypot_hits"
    ID_FIELD   = "hit_id"

    def by_ip(self, ip: str, limit: int = 50) -> List[dict]:
        return self.find_many({"src_ip": ip},
                              sort_field="timestamp", sort_desc=True, limit=limit)

    def by_service(self, service: str, limit: int = 50) -> List[dict]:
        return self.find_many({"service": service.upper()},
                              sort_field="timestamp", sort_desc=True, limit=limit)

    def recent(self, limit: int = 50) -> List[dict]:
        return self.find_many(sort_field="timestamp", sort_desc=True, limit=limit)


class NormalizerLogRepository(MongoRepository):
    """Stores normalised log entries submitted via API or collectors."""
    COLLECTION = "normalizer_logs"
    ID_FIELD   = "log_id"

    def by_source(self, source: str, limit: int = 100) -> List[dict]:
        return self.find_many({"source": source},
                              sort_field="timestamp", sort_desc=True, limit=limit)

    def by_event_type(self, event_type: str, limit: int = 100) -> List[dict]:
        return self.find_many({"event_type": event_type},
                              sort_field="timestamp", sort_desc=True, limit=limit)

    def recent(self, limit: int = 100) -> List[dict]:
        return self.find_many(sort_field="timestamp", sort_desc=True, limit=limit)
