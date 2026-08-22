"""
AHRAS — Alert & Report Submission System
Analysts can raise alerts and submit reports to Masters.
Masters can view, acknowledge, escalate, and close.
"""

import time
import threading
import uuid
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from enum import Enum


class AlertPriority(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    ESCALATED = "ESCALATED"


class ReportStatus(str, Enum):
    SUBMITTED = "SUBMITTED"
    UNDER_REVIEW = "UNDER_REVIEW"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


@dataclass
class AnalystAlert:
    """An alert raised by an analyst and sent to master."""
    alert_id: str
    title: str
    description: str
    priority: AlertPriority
    submitted_by: str
    target_ip: str = ""
    attack_type: str = ""
    event_ids: List[str] = field(default_factory=list)
    status: AlertStatus = AlertStatus.OPEN
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    acknowledged_by: str = ""
    acknowledged_at: Optional[float] = None
    master_notes: str = ""
    action_taken: str = ""

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "description": self.description,
            "priority": self.priority.value,
            "submitted_by": self.submitted_by,
            "target_ip": self.target_ip,
            "attack_type": self.attack_type,
            "event_ids": self.event_ids,
            "status": self.status.value,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.created_at)),
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.updated_at)),
            "acknowledged_by": self.acknowledged_by,
            "acknowledged_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.acknowledged_at)) if self.acknowledged_at else None,
            "master_notes": self.master_notes,
            "action_taken": self.action_taken,
        }


@dataclass
class AnalystReport:
    """A formal report submitted by analyst to master."""
    report_id: str
    title: str
    summary: str
    findings: str
    recommendations: str
    submitted_by: str
    severity: AlertPriority
    affected_ips: List[str] = field(default_factory=list)
    event_ids: List[str] = field(default_factory=list)
    status: ReportStatus = ReportStatus.SUBMITTED
    created_at: float = field(default_factory=time.time)
    reviewed_by: str = ""
    review_notes: str = ""
    reviewed_at: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "title": self.title,
            "summary": self.summary,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "submitted_by": self.submitted_by,
            "severity": self.severity.value,
            "affected_ips": self.affected_ips,
            "event_ids": self.event_ids,
            "status": self.status.value,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.created_at)),
            "reviewed_by": self.reviewed_by,
            "review_notes": self.review_notes,
            "reviewed_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.reviewed_at)) if self.reviewed_at else None,
        }


class AlertReportManager:
    """
    Manages the full lifecycle of analyst alerts and reports.
    Thread-safe. Persists to MongoDB; falls back to in-memory if unavailable.
    """

    def __init__(self):
        from database import AlertRepository
        self._repo = AlertRepository()
        self._repo.load_from_mongo(limit=2000)
        self._alerts: Dict[str, AnalystAlert] = {}
        self._reports: Dict[str, AnalystReport] = {}
        self._lock = threading.Lock()
        self._notifications: List[dict] = []

    # ── Alerts ────────────────────────────────────────────────────────────────

    def submit_alert(self, title: str, description: str, priority: str,
                     submitted_by: str, target_ip: str = "",
                     attack_type: str = "", event_ids: List[str] = None) -> AnalystAlert:
        alert = AnalystAlert(
            alert_id=f"ALT-{uuid.uuid4().hex[:8].upper()}",
            title=title,
            description=description,
            priority=AlertPriority(priority.upper()),
            submitted_by=submitted_by,
            target_ip=target_ip,
            attack_type=attack_type,
            event_ids=event_ids or [],
        )
        with self._lock:
            self._alerts[alert.alert_id] = alert
            self._repo.save(alert.to_dict())
            self._push_notification("NEW_ALERT", alert.alert_id,
                                    f"New {priority} alert from {submitted_by}: {title}")
        return alert

    def acknowledge_alert(self, alert_id: str, master_username: str,
                          notes: str = "", action: str = "") -> Optional[dict]:
        with self._lock:
            alert = self._alerts.get(alert_id)
            if not alert:
                return None
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_by = master_username
            alert.acknowledged_at = time.time()
            alert.master_notes = notes
            alert.action_taken = action
            alert.updated_at = time.time()
        return alert.to_dict()

    def update_alert_status(self, alert_id: str, status: str,
                            master_username: str, notes: str = "") -> Optional[dict]:
        with self._lock:
            alert = self._alerts.get(alert_id)
            if not alert:
                return None
            alert.status = AlertStatus(status.upper())
            alert.master_notes = notes
            alert.updated_at = time.time()
            if not alert.acknowledged_by:
                alert.acknowledged_by = master_username
        return alert.to_dict()

    def list_alerts(self, status_filter: str = None, limit: int = 50) -> List[dict]:
        with self._lock:
            alerts = sorted(self._alerts.values(),
                           key=lambda a: a.created_at, reverse=True)
            if status_filter:
                alerts = [a for a in alerts if a.status.value == status_filter.upper()]
            return [a.to_dict() for a in alerts[:limit]]

    # ── Reports ───────────────────────────────────────────────────────────────

    def submit_report(self, title: str, summary: str, findings: str,
                      recommendations: str, submitted_by: str,
                      severity: str, affected_ips: List[str] = None,
                      event_ids: List[str] = None) -> AnalystReport:
        report = AnalystReport(
            report_id=f"RPT-{uuid.uuid4().hex[:8].upper()}",
            title=title,
            summary=summary,
            findings=findings,
            recommendations=recommendations,
            submitted_by=submitted_by,
            severity=AlertPriority(severity.upper()),
            affected_ips=affected_ips or [],
            event_ids=event_ids or [],
        )
        with self._lock:
            self._reports[report.report_id] = report
            self._push_notification("NEW_REPORT", report.report_id,
                                    f"New report from {submitted_by}: {title}")
        return report

    def review_report(self, report_id: str, master_username: str,
                      status: str, notes: str = "") -> Optional[dict]:
        with self._lock:
            report = self._reports.get(report_id)
            if not report:
                return None
            report.status = ReportStatus(status.upper())
            report.reviewed_by = master_username
            report.review_notes = notes
            report.reviewed_at = time.time()
        return report.to_dict()

    def list_reports(self, limit: int = 50) -> List[dict]:
        with self._lock:
            reports = sorted(self._reports.values(),
                             key=lambda r: r.created_at, reverse=True)
            return [r.to_dict() for r in reports[:limit]]

    # ── Notifications (popup queue) ───────────────────────────────────────────

    def _push_notification(self, notif_type: str, ref_id: str, message: str):
        self._notifications.insert(0, {
            "id": uuid.uuid4().hex[:8],
            "type": notif_type,
            "ref_id": ref_id,
            "message": message,
            "timestamp": time.strftime("%H:%M:%S"),
            "read": False,
        })
        if len(self._notifications) > 100:
            self._notifications.pop()

    def get_notifications(self, unread_only: bool = False) -> List[dict]:
        with self._lock:
            notifs = self._notifications if not unread_only else [
                n for n in self._notifications if not n["read"]
            ]
            return notifs[:20]

    def mark_notifications_read(self):
        with self._lock:
            for n in self._notifications:
                n["read"] = True

    def unread_count(self) -> int:
        with self._lock:
            return sum(1 for n in self._notifications if not n["read"])

    def clear_notifications(self):
        with self._lock:
            self._notifications.clear()
