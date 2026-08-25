"""
AHRAS v4 — Forensics Module
Stores evidence, timelines, screenshots, logs, and investigation notes
tied to specific cases (incident IDs). Designed for realistic post-incident
investigation workflows used in real SOC environments.
"""

import os
import uuid
import time
import base64
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict

logger = logging.getLogger("ahras.forensics")

# Evidence types
EV_IP       = "malicious_ip"
EV_HASH     = "file_hash"
EV_LOG      = "log_entry"
EV_PCAP     = "packet_capture"
EV_SCREEN   = "screenshot"
EV_REGISTRY = "registry_key"
EV_FILE     = "file_artifact"
EV_MEMORY   = "memory_dump"
EV_OTHER    = "other"

VALID_EV_TYPES = {EV_IP, EV_HASH, EV_LOG, EV_PCAP, EV_SCREEN, EV_REGISTRY, EV_FILE, EV_MEMORY, EV_OTHER}


@dataclass
class EvidenceItem:
    evidence_id: str
    case_id: str
    ev_type: str        # see EV_* constants above
    title: str
    description: str
    data: str           # raw text, base64 blob, IP, hash, etc.
    source: str         # where this came from (e.g. "Windows Event Log", "Syslog")
    collected_by: str
    collected_at: str
    tags: List[str] = field(default_factory=list)
    hash_md5: str = ""
    hash_sha256: str = ""

    def to_dict(self) -> dict:
        return {
            "evidence_id": self.evidence_id,
            "case_id": self.case_id,
            "ev_type": self.ev_type,
            "title": self.title,
            "description": self.description,
            "data": self.data,
            "source": self.source,
            "collected_by": self.collected_by,
            "collected_at": self.collected_at,
            "tags": self.tags,
            "hash_md5": self.hash_md5,
            "hash_sha256": self.hash_sha256,
        }


@dataclass
class TimelineEvent:
    event_id: str
    case_id: str
    timestamp: str          # ISO-8601 string from analyst
    event_time_epoch: float
    actor: str              # IP, user, process, etc.
    action: str
    target: str
    description: str
    mitre_technique: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    severity: str = "INFO"  # INFO | LOW | MEDIUM | HIGH | CRITICAL
    added_by: str = "analyst"

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "case_id": self.case_id,
            "timestamp": self.timestamp,
            "event_time_epoch": self.event_time_epoch,
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
            "evidence_ids": self.evidence_ids,
            "severity": self.severity,
            "added_by": self.added_by,
        }


@dataclass
class InvestigationNote:
    note_id: str
    case_id: str
    title: str
    body: str
    author: str
    created_at: str
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "note_id": self.note_id,
            "case_id": self.case_id,
            "title": self.title,
            "body": self.body,
            "author": self.author,
            "created_at": self.created_at,
            "tags": self.tags,
        }


@dataclass
class ForensicCase:
    """Lightweight wrapper that aggregates all forensic artefacts for an incident."""
    case_id: str
    title: str
    status: str = "OPEN"    # OPEN | IN_PROGRESS | CLOSED
    created_at: str = ""
    analyst: str = ""
    evidence: List[EvidenceItem] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    notes: List[InvestigationNote] = field(default_factory=list)

    def to_dict(self) -> dict:
        tl_sorted = sorted(self.timeline, key=lambda e: e.event_time_epoch)
        return {
            "case_id": self.case_id,
            "title": self.title,
            "status": self.status,
            "created_at": self.created_at,
            "analyst": self.analyst,
            "evidence_count": len(self.evidence),
            "timeline_count": len(self.timeline),
            "note_count": len(self.notes),
            "evidence": [e.to_dict() for e in self.evidence],
            "timeline": [e.to_dict() for e in tl_sorted],
            "notes": [n.to_dict() for n in self.notes],
        }


class ForensicsManager:
    """
    Central manager for all forensic investigation data.
    Keyed by case_id so it can co-exist with CaseManager.
    """

    def __init__(self):
        from database import ForensicsRepository
        self._repo = ForensicsRepository()
        self._repo.load_from_mongo(limit=2000)
        self._cases: Dict[str, ForensicCase] = {}
        logger.info("ForensicsManager initialised (MongoDB-backed)")

    # ── Case management ──────────────────────────────────────────────────────

    def create_case(self, case_id: str, title: str, analyst: str = "unknown") -> ForensicCase:
        if case_id in self._cases:
            return self._cases[case_id]
        fc = ForensicCase(
            case_id=case_id,
            title=title,
            analyst=analyst,
            created_at=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        )
        self._cases[case_id] = fc
        self._repo.save(fc.to_dict())
        logger.info(f"Forensic case created: {case_id} — {title}")
        return fc

    def get_case(self, case_id: str) -> Optional[ForensicCase]:
        return self._cases.get(case_id)

    def list_cases(self, status: str = None) -> List[dict]:
        cases = list(self._cases.values())
        if status:
            cases = [c for c in cases if c.status.upper() == status.upper()]
        return [c.to_dict() for c in cases]

    def update_case_status(self, case_id: str, status: str) -> bool:
        c = self._cases.get(case_id)
        if not c:
            return False
        c.status = status.upper()
        return True

    # ── Evidence ─────────────────────────────────────────────────────────────

    def add_evidence(self, case_id: str, ev_type: str, title: str,
                     description: str, data: str, source: str,
                     collected_by: str = "analyst",
                     tags: List[str] = None,
                     hash_md5: str = "", hash_sha256: str = "") -> Optional[EvidenceItem]:
        """Add a piece of evidence to a forensic case. Creates the case if missing."""
        if case_id not in self._cases:
            self.create_case(case_id, f"Auto-created for {case_id}")

        if ev_type not in VALID_EV_TYPES:
            ev_type = EV_OTHER

        ev = EvidenceItem(
            evidence_id=f"EV-{uuid.uuid4().hex[:8].upper()}",
            case_id=case_id,
            ev_type=ev_type,
            title=title,
            description=description,
            data=data,
            source=source,
            collected_by=collected_by,
            collected_at=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
            tags=tags or [],
            hash_md5=hash_md5,
            hash_sha256=hash_sha256,
        )
        self._cases[case_id].evidence.append(ev)
        logger.info(f"Evidence {ev.evidence_id} added to case {case_id}")
        return ev

    def list_evidence(self, case_id: str) -> List[dict]:
        c = self._cases.get(case_id)
        if not c:
            return []
        return [e.to_dict() for e in c.evidence]

    def delete_evidence(self, case_id: str, evidence_id: str) -> bool:
        c = self._cases.get(case_id)
        if not c:
            return False
        before = len(c.evidence)
        c.evidence = [e for e in c.evidence if e.evidence_id != evidence_id]
        return len(c.evidence) < before

    # ── Timeline ─────────────────────────────────────────────────────────────

    def add_timeline_event(self, case_id: str, timestamp: str, actor: str,
                           action: str, target: str, description: str,
                           mitre_technique: str = "", severity: str = "INFO",
                           evidence_ids: List[str] = None,
                           added_by: str = "analyst") -> Optional[TimelineEvent]:
        if case_id not in self._cases:
            self.create_case(case_id, f"Auto-created for {case_id}")

        try:
            import datetime
            epoch = datetime.datetime.fromisoformat(timestamp).timestamp()
        except Exception:
            epoch = time.time()

        te = TimelineEvent(
            event_id=f"TL-{uuid.uuid4().hex[:8].upper()}",
            case_id=case_id,
            timestamp=timestamp,
            event_time_epoch=epoch,
            actor=actor,
            action=action,
            target=target,
            description=description,
            mitre_technique=mitre_technique,
            evidence_ids=evidence_ids or [],
            severity=severity.upper(),
            added_by=added_by,
        )
        self._cases[case_id].timeline.append(te)
        logger.info(f"Timeline event {te.event_id} added to case {case_id}")
        return te

    def get_timeline(self, case_id: str) -> List[dict]:
        c = self._cases.get(case_id)
        if not c:
            return []
        return [e.to_dict() for e in sorted(c.timeline, key=lambda x: x.event_time_epoch)]

    # ── Investigation Notes ──────────────────────────────────────────────────

    def add_note(self, case_id: str, title: str, body: str,
                 author: str = "analyst", tags: List[str] = None) -> Optional[InvestigationNote]:
        if case_id not in self._cases:
            self.create_case(case_id, f"Auto-created for {case_id}")

        note = InvestigationNote(
            note_id=f"NOTE-{uuid.uuid4().hex[:8].upper()}",
            case_id=case_id,
            title=title,
            body=body,
            author=author,
            created_at=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
            tags=tags or [],
        )
        self._cases[case_id].notes.append(note)
        logger.info(f"Note {note.note_id} added to case {case_id}")
        return note

    def list_notes(self, case_id: str) -> List[dict]:
        c = self._cases.get(case_id)
        if not c:
            return []
        return [n.to_dict() for n in c.notes]

    def update_note(self, case_id: str, note_id: str, body: str) -> bool:
        c = self._cases.get(case_id)
        if not c:
            return False
        for note in c.notes:
            if note.note_id == note_id:
                note.body = body
                return True
        return False

    # ── Summary ──────────────────────────────────────────────────────────────

    def get_summary(self, case_id: str) -> dict:
        c = self._cases.get(case_id)
        if not c:
            return {"error": "Case not found"}
        ev_by_type: Dict[str, int] = {}
        for e in c.evidence:
            ev_by_type[e.ev_type] = ev_by_type.get(e.ev_type, 0) + 1
        return {
            "case_id": case_id,
            "title": c.title,
            "status": c.status,
            "analyst": c.analyst,
            "created_at": c.created_at,
            "evidence_count": len(c.evidence),
            "evidence_by_type": ev_by_type,
            "timeline_events": len(c.timeline),
            "notes_count": len(c.notes),
            "first_event": c.timeline[0].timestamp if c.timeline else None,
            "last_event": sorted(c.timeline, key=lambda x: x.event_time_epoch)[-1].timestamp if c.timeline else None,
        }
