"""
AHRAS v7 — MongoDB Repository Base
=====================================
Base class for all MongoDB-backed data stores.
Provides standard CRUD with automatic fallback to the in-memory dict
when MongoDB is unavailable.

Usage:
    class AlertRepository(MongoRepository):
        COLLECTION = "alerts"
        ID_FIELD   = "alert_id"

    repo = AlertRepository()
    repo.save({"alert_id": "ALT-001", "severity": "HIGH", ...})
    repo.find_by_id("ALT-001")
    repo.find_many({"severity": "HIGH"}, limit=50)
    repo.update("ALT-001", {"status": "ACKNOWLEDGED"})
    repo.delete("ALT-001")
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from database.connection import get_collection, is_connected

logger = logging.getLogger("ahras.database.repo")


class MongoRepository:
    """
    Abstract base repository.
    Subclass and set COLLECTION and ID_FIELD.
    """
    COLLECTION: str = "base"   # override in subclass
    ID_FIELD:   str = "_id"    # override in subclass (e.g. "alert_id")

    def __init__(self):
        self._memory: Dict[str, dict] = {}   # fallback store
        self._col_name = self.COLLECTION

    # ── Internal helpers ─────────────────────────────────────────────────────

    @property
    def _col(self):
        return get_collection(self._col_name)

    def _now_dt(self):
        return datetime.now(timezone.utc)

    def _stamp(self, doc: dict) -> dict:
        """Add created_at / updated_at datetime fields for TTL indexes."""
        now = self._now_dt()
        doc.setdefault("created_at_dt", now)
        doc["updated_at_dt"] = now
        return doc

    # ── Core CRUD ─────────────────────────────────────────────────────────────

    def save(self, doc: dict) -> bool:
        """
        Insert or update (upsert) a document.
        Uses the ID_FIELD value as the unique key.
        Returns True on success.
        """
        doc = self._stamp(dict(doc))
        key = doc.get(self.ID_FIELD)
        if not key:
            logger.warning(f"save() called without {self.ID_FIELD} — skipping")
            return False

        col = self._col
        if col is not None:
            try:
                col.replace_one({self.ID_FIELD: key}, doc, upsert=True)
                # Also keep in memory for fast local reads
                self._memory[key] = doc
                return True
            except Exception as e:
                logger.error(f"MongoDB save error [{self._col_name}]: {e}")
                # Fallback to memory
                self._memory[key] = doc
                return True
        else:
            self._memory[key] = doc
            return True

    def find_by_id(self, key: str) -> Optional[dict]:
        """Return a single document by its ID_FIELD value."""
        # Try memory first (faster)
        if key in self._memory:
            return dict(self._memory[key])

        col = self._col
        if col is not None:
            try:
                doc = col.find_one({self.ID_FIELD: key}, {"_id": 0})
                if doc:
                    self._memory[key] = doc   # warm local cache
                    return dict(doc)
            except Exception as e:
                logger.error(f"MongoDB find_by_id error: {e}")
        return None

    def find_many(self, query: dict = None, sort_field: str = None,
                  sort_desc: bool = True, limit: int = 100,
                  skip: int = 0) -> List[dict]:
        """Return multiple documents matching query dict."""
        query = query or {}
        col = self._col
        if col is not None:
            try:
                cursor = col.find(query, {"_id": 0})
                if sort_field:
                    direction = -1 if sort_desc else 1
                    cursor = cursor.sort(sort_field, direction)
                cursor = cursor.skip(skip).limit(limit)
                results = list(cursor)
                # Warm memory cache
                for doc in results:
                    k = doc.get(self.ID_FIELD)
                    if k:
                        self._memory[k] = doc
                return results
            except Exception as e:
                logger.error(f"MongoDB find_many error: {e}")

        # Fallback: filter in memory
        results = [v for v in self._memory.values()
                   if all(v.get(k) == val for k, val in query.items())]
        if sort_field:
            results.sort(key=lambda x: x.get(sort_field, 0), reverse=sort_desc)
        return results[skip: skip + limit]

    def update(self, key: str, fields: dict) -> bool:
        """Update specific fields on an existing document."""
        fields["updated_at_dt"] = self._now_dt()
        col = self._col
        if col is not None:
            try:
                col.update_one({self.ID_FIELD: key}, {"$set": fields})
                if key in self._memory:
                    self._memory[key].update(fields)
                return True
            except Exception as e:
                logger.error(f"MongoDB update error: {e}")

        # Fallback
        if key in self._memory:
            self._memory[key].update(fields)
            return True
        return False

    def delete(self, key: str) -> bool:
        """Delete a document by its ID_FIELD value."""
        col = self._col
        if col is not None:
            try:
                result = col.delete_one({self.ID_FIELD: key})
                self._memory.pop(key, None)
                return result.deleted_count > 0
            except Exception as e:
                logger.error(f"MongoDB delete error: {e}")

        return bool(self._memory.pop(key, None))

    def count(self, query: dict = None) -> int:
        """Return the number of documents matching query."""
        query = query or {}
        col = self._col
        if col is not None:
            try:
                return col.count_documents(query)
            except Exception as e:
                logger.error(f"MongoDB count error: {e}")

        # Fallback
        if not query:
            return len(self._memory)
        return sum(1 for v in self._memory.values()
                   if all(v.get(k) == val for k, val in query.items()))

    def all(self, limit: int = 1000) -> List[dict]:
        """Return all documents (up to limit)."""
        return self.find_many(limit=limit)

    def load_from_mongo(self, limit: int = 5000):
        """
        Load existing MongoDB documents into local memory cache on startup.
        Call this once during module init to warm the cache.
        """
        col = self._col
        if col is None:
            return
        try:
            docs = list(col.find({}, {"_id": 0}).limit(limit))
            for doc in docs:
                k = doc.get(self.ID_FIELD)
                if k:
                    self._memory[k] = doc
            logger.info(f"Loaded {len(docs)} {self._col_name} docs from MongoDB")
        except Exception as e:
            logger.warning(f"Could not pre-load {self._col_name}: {e}")

    # ── Aggregation helpers ───────────────────────────────────────────────────

    def group_count(self, field: str) -> Dict[str, int]:
        """
        Return a dict of {field_value: count} for all documents.
        Example: group_count("severity") → {"HIGH": 45, "LOW": 120}
        """
        col = self._col
        if col is not None:
            try:
                pipeline = [
                    {"$group": {"_id": f"${field}", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}}
                ]
                return {doc["_id"]: doc["count"]
                        for doc in col.aggregate(pipeline)
                        if doc["_id"]}
            except Exception as e:
                logger.error(f"MongoDB group_count error: {e}")

        # Fallback
        result: Dict[str, int] = {}
        for v in self._memory.values():
            k = v.get(field, "unknown")
            result[k] = result.get(k, 0) + 1
        return result

    def latest(self, n: int = 10, sort_field: str = "created_at") -> List[dict]:
        """Return the N most recently created documents."""
        return self.find_many(sort_field=sort_field, sort_desc=True, limit=n)
