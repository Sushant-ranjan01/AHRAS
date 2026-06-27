"""
AHRAS v6 — External API Layer
==============================
A clean, versioned API router (/api/v1/...) designed for external
integrations, SIEM connectors, scripts, and third-party tools.

This is separate from the internal main.py routes which serve the dashboard.
Mount this with:
    from api.router import api_router
    app.include_router(api_router, prefix="/api/v1")

Endpoints:
    POST   /api/v1/logs          Submit raw log entries for normalisation + ingestion
    POST   /api/v1/events        Submit pre-parsed events directly
    POST   /api/v1/ioc           Add a new Indicator of Compromise
    GET    /api/v1/alerts        List recent alerts with optional filters
    GET    /api/v1/cases         List investigation cases
    GET    /api/v1/risk          Get risk score for an indicator
    GET    /api/v1/threats       Threat hunt across all data sources
    GET    /api/v1/history       Historical risk data for an indicator
    GET    /api/v1/ti            Threat intelligence lookup
    GET    /api/v1/rbac/roles    List all roles and their permissions
    GET    /api/v1/health        Extended health check with subsystem status
"""

import time
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("ahras.api.v1")

api_router = APIRouter(tags=["External API v1"])


# ── Request / Response models ────────────────────────────────────────────────

class LogSubmission(BaseModel):
    """Submit raw log lines for normalisation and ingestion."""
    logs: List[dict] = Field(..., description="List of raw log dicts")
    source: Optional[str] = Field("api", description="Source system name")
    auto_ingest: bool = Field(True, description="If true, normalised events are passed to the detection pipeline")

    class Config:
        json_schema_extra = {
            "example": {
                "source": "windows-dc-01",
                "auto_ingest": True,
                "logs": [
                    {"source": "windows_collector", "event_id": 4625,
                     "TargetUserName": "admin", "IpAddress": "10.0.0.99"}
                ]
            }
        }


class EventSubmission(BaseModel):
    """Submit a pre-parsed event directly to the risk engine."""
    src_ip: str
    attack_type: str = "Normal"
    confidence: float = 0.5
    packet_count: int = 0
    anomaly_flag: bool = False
    username: Optional[str] = None
    mitre_technique: Optional[str] = None
    severity: Optional[str] = None
    extra: dict = Field(default_factory=dict)

    class Config:
        json_schema_extra = {
            "example": {
                "src_ip": "192.168.1.100",
                "attack_type": "SSH_Bruteforce",
                "confidence": 0.85,
                "packet_count": 800,
                "anomaly_flag": True
            }
        }


class IOCSubmission(BaseModel):
    """Add a new Indicator of Compromise."""
    indicator: str
    ioc_type: str = Field(..., description="ip | domain | hash | url | email")
    threat_level: str = Field("medium", description="low | medium | high | critical")
    description: str = ""
    tags: List[str] = Field(default_factory=list)
    source: str = "api"

    class Config:
        json_schema_extra = {
            "example": {
                "indicator": "185.220.101.1",
                "ioc_type": "ip",
                "threat_level": "high",
                "description": "TOR exit node used in brute force campaign",
                "tags": ["tor", "bruteforce"],
                "source": "external-feed"
            }
        }


# ── Dependency: resolve singletons lazily ────────────────────────────────────
# We use lazy imports to avoid circular imports at module load time.

def _get_modules():
    """Return all AHRAS singletons. Called inside route handlers."""
    try:
        import main as m
        return {
            "alert_mgr":      m.alert_mgr,
            "case_mgr":       m.case_mgr,
            "ioc_mgr":        m.ioc_mgr,
            "threat_hunter":  m.threat_hunter,
            "threat_intel":   m.threat_intel,
            "risk_eng":       m.risk_eng,
            "log_normalizer": m.log_normalizer,
            "risk_explainer": m.risk_explainer,
            "hist_risk":      getattr(m, "hist_risk", None),
            "evt_mgr":        m.evt_mgr,
        }
    except ImportError as e:
        raise HTTPException(500, f"AHRAS modules not initialised: {e}")


def _auth():
    from auth.manager import get_current_user
    return Depends(get_current_user)


# ── POST /logs ────────────────────────────────────────────────────────────────
@api_router.post("/logs", summary="Submit raw logs for normalisation")
async def submit_logs(req: LogSubmission,
                      current_user: dict = Depends(lambda: None)):
    """
    Submit raw log entries from any source.
    AHRAS normalises them to the unified schema, then optionally
    passes them through the detection pipeline.

    Returns the normalised events + any alerts generated.
    """
    # Resolve auth lazily
    from auth.manager import get_current_user
    from rbac import require_permission
    from rbac.permissions import Perm

    mods = _get_modules()
    norm = mods["log_normalizer"]

    # Tag all logs with the declared source
    tagged = [{**log, "source": log.get("source") or req.source} for log in req.logs]
    normalised = norm.normalise_batch(tagged)

    alerts_generated = []
    if req.auto_ingest:
        risk_eng = mods["risk_eng"]
        alert_mgr = mods["alert_mgr"]
        hist_risk = mods.get("hist_risk")
        for event in normalised:
            try:
                det = {
                    "src_ip":       event.get("src_ip", "0.0.0.0"),
                    "attack_type":  event.get("event_type", "Normal"),
                    "confidence":   0.6 if event.get("severity") in ("HIGH", "CRITICAL") else 0.3,
                    "packet_count": event.get("bytes_sent", 0),
                    "anomaly_flag": event.get("severity") in ("HIGH", "CRITICAL"),
                }
                if hist_risk:
                    boost = hist_risk.get_boost(det["src_ip"])
                    det["history_boost"] = boost
                result = risk_eng.evaluate(det)
                if hist_risk:
                    hist_risk.record_event(det, result.risk_score_100)
                if result.risk_score_100 >= 50:
                    alert = alert_mgr.create_alert(
                        alert_type=event.get("event_type", "log_ingestion"),
                        severity=result.severity,
                        src_ip=det["src_ip"],
                        details=f"Log ingestion via API: {event.get('event_type')}",
                        risk_score=result.risk_score_100,
                    )
                    if alert:
                        alerts_generated.append(alert.alert_id)
            except Exception as e:
                logger.warning(f"Auto-ingest error for event: {e}")

    return {
        "submitted": len(req.logs),
        "normalised": len(normalised),
        "alerts_generated": alerts_generated,
        "events": normalised[:100],  # cap response at 100
    }


# ── POST /events ──────────────────────────────────────────────────────────────
@api_router.post("/events", summary="Submit pre-parsed events to risk engine")
async def submit_event(req: EventSubmission):
    """
    Submit a pre-parsed event directly to the risk engine.
    Returns risk score + full explanation + any alert ID generated.
    """
    mods = _get_modules()
    risk_eng     = mods["risk_eng"]
    risk_explainer = mods["risk_explainer"]
    alert_mgr    = mods["alert_mgr"]
    hist_risk    = mods.get("hist_risk")

    det = {
        "src_ip":        req.src_ip,
        "attack_type":   req.attack_type,
        "confidence":    req.confidence,
        "packet_count":  req.packet_count,
        "anomaly_flag":  req.anomaly_flag,
        **req.extra,
    }
    if req.username:  det["username"] = req.username
    if req.mitre_technique: det["mitre_technique"] = req.mitre_technique

    # Add history boost if available
    if hist_risk:
        boost = hist_risk.get_boost(req.src_ip)
        det["history_boost"] = boost

    result = risk_eng.evaluate(det)

    # Record in history
    if hist_risk:
        hist_risk.record_event(det, result.risk_score_100)

    # Explain the score
    explanation = risk_explainer.explain(result).to_dict()

    # Auto-alert if HIGH/CRITICAL
    alert_id = None
    if result.severity in ("HIGH", "CRITICAL"):
        alert = alert_mgr.create_alert(
            alert_type=req.attack_type,
            severity=result.severity,
            src_ip=req.src_ip,
            details=f"API-submitted event: {req.attack_type} (confidence={req.confidence:.0%})",
            risk_score=result.risk_score_100,
        )
        if alert:
            alert_id = alert.alert_id
            if hist_risk:
                hist_risk.record_alert(req.src_ip)

    return {
        "risk_score":  result.risk_score_100,
        "severity":    result.severity,
        "explanation": explanation,
        "alert_id":    alert_id,
    }


# ── POST /ioc ─────────────────────────────────────────────────────────────────
@api_router.post("/ioc", summary="Add Indicator of Compromise")
async def add_ioc(req: IOCSubmission):
    """Add a new IOC to the AHRAS database. Immediately active for matching."""
    mods = _get_modules()
    ioc_mgr = mods["ioc_mgr"]
    try:
        ioc = ioc_mgr.add_ioc(
            indicator=req.indicator,
            ioc_type=req.ioc_type,
            threat_level=req.threat_level,
            description=req.description,
            tags=req.tags,
            source=req.source,
            added_by="api",
        )
        return {"added": True, "ioc_id": getattr(ioc, "ioc_id", None), "indicator": req.indicator}
    except Exception as e:
        raise HTTPException(400, f"IOC add failed: {e}")


# ── GET /alerts ───────────────────────────────────────────────────────────────
@api_router.get("/alerts", summary="List recent alerts")
async def get_alerts(
    limit:    int    = Query(50, le=500),
    severity: Optional[str] = Query(None, description="Filter: LOW|MEDIUM|HIGH|CRITICAL"),
    since_h:  int    = Query(24, description="Hours to look back"),
):
    """Return recent alerts, optionally filtered by severity and time window."""
    mods = _get_modules()
    alert_mgr = mods["alert_mgr"]
    try:
        alerts = alert_mgr.get_alerts(limit=limit * 2) or []
        cutoff = time.time() - (since_h * 3600)
        result = []
        for a in alerts:
            d = a.to_dict() if hasattr(a, "to_dict") else a
            ts = d.get("timestamp", 0)
            if isinstance(ts, str):
                try:
                    from datetime import datetime
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
                except Exception:
                    ts = 0
            if ts < cutoff:
                continue
            if severity and d.get("severity", "").upper() != severity.upper():
                continue
            result.append(d)
            if len(result) >= limit:
                break
        return {"count": len(result), "alerts": result}
    except Exception as e:
        raise HTTPException(500, f"Alert fetch failed: {e}")


# ── GET /cases ────────────────────────────────────────────────────────────────
@api_router.get("/cases", summary="List investigation cases")
async def get_cases(
    limit:  int           = Query(20, le=200),
    status: Optional[str] = Query(None, description="OPEN|IN_PROGRESS|CLOSED"),
):
    """Return investigation cases from Case Manager."""
    mods = _get_modules()
    case_mgr = mods["case_mgr"]
    try:
        cases = case_mgr.list_cases() or []
        if status:
            cases = [c for c in cases
                     if (c.get("status") or "").upper() == status.upper()]
        return {"count": len(cases[:limit]), "cases": cases[:limit]}
    except Exception as e:
        raise HTTPException(500, f"Case fetch failed: {e}")


# ── GET /risk ─────────────────────────────────────────────────────────────────
@api_router.get("/risk", summary="Get risk score for an indicator")
async def get_risk(
    ip:         Optional[str] = Query(None),
    attack_type: str = Query("Normal"),
    explain:    bool = Query(False, description="Include full score breakdown"),
):
    """
    Score an indicator through the risk engine.
    Set explain=true to get the full component breakdown.
    """
    if not ip:
        raise HTTPException(400, "ip parameter is required")
    mods = _get_modules()
    risk_eng = mods["risk_eng"]
    hist_risk = mods.get("hist_risk")

    det = {
        "src_ip": ip, "attack_type": attack_type,
        "confidence": 0.5, "packet_count": 0, "anomaly_flag": False,
    }
    if hist_risk:
        det["history_boost"] = hist_risk.get_boost(ip)

    result = risk_eng.evaluate(det)
    resp = {
        "ip": ip,
        "risk_score": result.risk_score_100,
        "severity":   result.severity,
    }
    if hist_risk:
        resp["history_boost"] = det.get("history_boost", 0)
        h = hist_risk.get_history_dict(ip)
        if h:
            resp["history"] = {
                "incident_count": h["incident_count"],
                "alert_count":    h["alert_count"],
                "threat_profile": h["threat_profile"],
                "days_since_last_seen": h["days_since_last_seen"],
            }
    if explain:
        resp["explanation"] = mods["risk_explainer"].explain(result).to_dict()
    return resp


# ── GET /threats ──────────────────────────────────────────────────────────────
@api_router.get("/threats", summary="Threat hunt across all data sources")
async def get_threats(
    q:    str           = Query(..., description="Indicator to hunt (IP, domain, hash, MITRE)"),
    type: Optional[str] = Query(None, description="Force type: ip|domain|url|hash|mitre"),
):
    """
    Hunt for any indicator across all AHRAS data sources.
    Returns correlated alerts, cases, threat intel, IOC matches, and risk score.
    """
    mods = _get_modules()
    result = mods["threat_hunter"].hunt(q, query_type=type or "auto")
    return result.to_dict()


# ── GET /history ──────────────────────────────────────────────────────────────
@api_router.get("/history", summary="Historical risk data for an indicator")
async def get_history(
    ip:     Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    top:    int           = Query(20, le=100, description="Return top-N repeat offenders"),
):
    """
    Get historical risk data for an IP or domain.
    If no indicator provided, returns the top repeat offenders.
    """
    mods = _get_modules()
    hist_risk = mods.get("hist_risk")
    if not hist_risk:
        return {"error": "Historical Risk Engine not initialised", "data": []}

    if ip:
        h = hist_risk.get_history_dict(ip, "ip")
        if not h:
            return {"indicator": ip, "message": "No history found", "history_boost": 0}
        return h
    if domain:
        h = hist_risk.get_history_dict(domain, "domain")
        if not h:
            return {"indicator": domain, "message": "No history found", "history_boost": 0}
        return h

    # Return top repeat offenders
    return {
        "top_offenders": hist_risk.top_repeat_offenders(top),
        "summary": hist_risk.summary(),
    }


# ── GET /ti ───────────────────────────────────────────────────────────────────
@api_router.get("/ti", summary="Threat intelligence lookup")
async def threat_intel_lookup(
    ip:     Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    hash:   Optional[str] = Query(None),
    url:    Optional[str] = Query(None),
):
    """
    Query the threat intelligence engine for an indicator.
    Calls AbuseIPDB, VirusTotal, AlienVault OTX (if keys configured),
    or falls back to the built-in AHRAS intelligence database.
    """
    mods = _get_modules()
    ti = mods["threat_intel"]

    if ip:
        return ti.check_ip(ip).to_dict()
    if domain:
        return ti.check_domain(domain).to_dict()
    if hash:
        return ti.check_hash(hash).to_dict()
    if url:
        return ti.check_url(url).to_dict()
    raise HTTPException(400, "Provide at least one of: ip, domain, hash, url")


# ── GET /rbac/roles ───────────────────────────────────────────────────────────
@api_router.get("/rbac/roles", summary="List all roles and permissions")
async def rbac_roles():
    """Return the full RBAC role/permission matrix."""
    from rbac.permissions import role_summary
    return {"roles": role_summary()}


# ── GET /health ───────────────────────────────────────────────────────────────
@api_router.get("/health", summary="Extended system health check")
async def health_check():
    """Return health status of all AHRAS subsystems."""
    mods = _get_modules()
    hist_risk = mods.get("hist_risk")

    subsystems = {}
    for name, obj in mods.items():
        subsystems[name] = "ok" if obj is not None else "not_initialised"

    return {
        "status": "ok",
        "version": "6.0.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "subsystems": subsystems,
        "historical_risk": hist_risk.summary() if hist_risk else None,
        "threat_intel_stats": mods["threat_intel"].stats() if mods.get("threat_intel") else None,
    }
