"""AHRAS — Case Management System
Full SOC incident lifecycle: Alert → Case → Assignment → Investigation → Resolution → Closure
"""
import time
import uuid
import threading
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum

logger = logging.getLogger("ahras.cases")


class CaseStatus(str, Enum):
    OPEN = "OPEN"
    ASSIGNED = "ASSIGNED"
    IN_INVESTIGATION = "IN_INVESTIGATION"
    PENDING_CLOSURE = "PENDING_CLOSURE"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class CasePriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class CaseNote:
    note_id: str
    author: str
    content: str
    timestamp: float = field(default_factory=time.time)
    note_type: str = "note"  # note, evidence, action, escalation

    def to_dict(self) -> dict:
        return {
            "note_id": self.note_id,
            "author": self.author,
            "content": self.content,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)),
            "note_type": self.note_type,
        }


@dataclass
class Case:
    case_id: str
    title: str
    description: str
    priority: CasePriority
    status: CaseStatus
    created_by: str
    assigned_to: str = ""
    mitre_technique: str = ""
    mitre_tactic: str = ""
    attack_type: str = ""
    affected_ips: List[str] = field(default_factory=list)
    event_ids: List[str] = field(default_factory=list)
    alert_ids: List[str] = field(default_factory=list)
    notes: List[CaseNote] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    resolution: str = ""
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    closed_at: Optional[float] = None
    sla_hours: int = 24

    @property
    def age_hours(self) -> float:
        return (time.time() - self.created_at) / 3600

    @property
    def sla_breached(self) -> bool:
        return self.status not in (CaseStatus.CLOSED, CaseStatus.FALSE_POSITIVE) and self.age_hours > self.sla_hours

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "description": self.description,
            "priority": self.priority.value,
            "status": self.status.value,
            "created_by": self.created_by,
            "assigned_to": self.assigned_to,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "attack_type": self.attack_type,
            "affected_ips": self.affected_ips,
            "event_ids": self.event_ids,
            "alert_ids": self.alert_ids,
            "notes": [n.to_dict() for n in self.notes],
            "tags": self.tags,
            "resolution": self.resolution,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.created_at)),
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.updated_at)),
            "closed_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.closed_at)) if self.closed_at else None,
            "age_hours": round(self.age_hours, 1),
            "sla_hours": self.sla_hours,
            "sla_breached": self.sla_breached,
            "note_count": len(self.notes),
        }


_SLA_BY_PRIORITY = {
    CasePriority.LOW: 72,
    CasePriority.MEDIUM: 24,
    CasePriority.HIGH: 8,
    CasePriority.CRITICAL: 2,
}


class CaseManager:
    """Full incident case lifecycle manager."""

    _ctr = 0
    _ctr_lock = threading.Lock()

    def __init__(self):
        from database import CaseRepository
        self._repo = CaseRepository()
        self._repo.load_from_mongo(limit=5000)
        self._cases: Dict[str, Case] = {}
        self._lock = threading.Lock()
        # Sync counter from MongoDB
        count = self._repo.count()
        if count > CaseManager._ctr:
            CaseManager._ctr = count
        logger.info(f"CaseManager ready — {count} cases loaded from MongoDB")

    def _next_id(self) -> str:
        with CaseManager._ctr_lock:
            CaseManager._ctr += 1
            return f"CASE-{CaseManager._ctr:04d}"

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def create_case(self, title: str, description: str, priority: str,
                    created_by: str, attack_type: str = "",
                    affected_ips: List[str] = None, event_ids: List[str] = None,
                    alert_ids: List[str] = None, mitre_technique: str = "",
                    mitre_tactic: str = "", tags: List[str] = None) -> Case:
        prio = CasePriority(priority.upper())
        case = Case(
            case_id=self._next_id(),
            title=title,
            description=description,
            priority=prio,
            status=CaseStatus.OPEN,
            created_by=created_by,
            attack_type=attack_type,
            affected_ips=affected_ips or [],
            event_ids=event_ids or [],
            alert_ids=alert_ids or [],
            mitre_technique=mitre_technique,
            mitre_tactic=mitre_tactic,
            tags=tags or [],
            sla_hours=_SLA_BY_PRIORITY[prio],
        )
        with self._lock:
            self._cases[case.case_id] = case
            self._repo.save(case.to_dict())
        logger.info(f"Case {case.case_id} created by {created_by}: {title}")
        return case

    def get_case(self, case_id: str) -> Optional[Case]:
        with self._lock:
            return self._cases.get(case_id)

    def list_cases(self, status: str = None, priority: str = None,
                   assigned_to: str = None, limit: int = 50) -> List[dict]:
        with self._lock:
            results = list(self._cases.values())
        if status:
            results = [c for c in results if c.status.value == status.upper()]
        if priority:
            results = [c for c in results if c.priority.value == priority.upper()]
        if assigned_to:
            results = [c for c in results if c.assigned_to == assigned_to]
        results.sort(key=lambda x: x.created_at, reverse=True)
        return [c.to_dict() for c in results[:limit]]

    def assign_case(self, case_id: str, assigned_to: str, assigned_by: str) -> Optional[dict]:
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                return None
            case.assigned_to = assigned_to
            case.status = CaseStatus.ASSIGNED
            case.updated_at = time.time()
            case.notes.append(CaseNote(
                note_id=str(uuid.uuid4())[:8],
                author=assigned_by,
                content=f"Case assigned to {assigned_to}",
                note_type="action"
            ))
        return case.to_dict()

    def update_status(self, case_id: str, status: str, updated_by: str, note: str = "") -> Optional[dict]:
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                return None
            old_status = case.status.value
            case.status = CaseStatus(status.upper())
            case.updated_at = time.time()
            if case.status in (CaseStatus.CLOSED, CaseStatus.FALSE_POSITIVE):
                case.closed_at = time.time()
            if note or old_status != status.upper():
                content = f"Status changed: {old_status} → {status.upper()}"
                if note:
                    content += f"\nNote: {note}"
                case.notes.append(CaseNote(
                    note_id=str(uuid.uuid4())[:8],
                    author=updated_by,
                    content=content,
                    note_type="action"
                ))
        return case.to_dict()

    def add_note(self, case_id: str, author: str, content: str,
                 note_type: str = "note") -> Optional[dict]:
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                return None
            note = CaseNote(
                note_id=str(uuid.uuid4())[:8],
                author=author,
                content=content,
                note_type=note_type
            )
            case.notes.append(note)
            case.updated_at = time.time()
        return case.to_dict()

    def resolve_case(self, case_id: str, resolved_by: str, resolution: str) -> Optional[dict]:
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                return None
            case.resolution = resolution
            case.status = CaseStatus.PENDING_CLOSURE
            case.updated_at = time.time()
            case.notes.append(CaseNote(
                note_id=str(uuid.uuid4())[:8],
                author=resolved_by,
                content=f"Resolution: {resolution}",
                note_type="action"
            ))
        return case.to_dict()

    def close_case(self, case_id: str, closed_by: str, notes: str = "") -> Optional[dict]:
        with self._lock:
            case = self._cases.get(case_id)
            if not case:
                return None
            case.status = CaseStatus.CLOSED
            case.closed_at = time.time()
            case.updated_at = time.time()
            if notes:
                case.notes.append(CaseNote(
                    note_id=str(uuid.uuid4())[:8],
                    author=closed_by,
                    content=f"Case closed. {notes}",
                    note_type="action"
                ))
        logger.info(f"Case {case_id} closed by {closed_by}")
        return case.to_dict()

    def stats(self) -> dict:
        with self._lock:
            cases = list(self._cases.values())
        by_status = {}
        by_priority = {}
        sla_breached = 0
        for c in cases:
            s = c.status.value
            p = c.priority.value
            by_status[s] = by_status.get(s, 0) + 1
            by_priority[p] = by_priority.get(p, 0) + 1
            if c.sla_breached:
                sla_breached += 1
        open_cases = [c for c in cases if c.status not in (CaseStatus.CLOSED, CaseStatus.FALSE_POSITIVE)]
        return {
            "total": len(cases),
            "open": len(open_cases),
            "by_status": by_status,
            "by_priority": by_priority,
            "sla_breached": sla_breached,
        }
