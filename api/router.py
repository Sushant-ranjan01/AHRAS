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
    GET    /api/v1/features      Self-describing one-line list of every module
    GET    /api/v1/health        Extended health check with subsystem status
    POST   /api/v1/graph/predict-paths   Temporal-graph multi-hop attack path prediction
    POST   /api/v1/soar/copilot/narrative  LLM (or template) incident note + exec summary
    POST   /api/v1/ztre/session          Continuous Zero-Trust session risk re-evaluation
    GET    /api/v1/ztre/sessions         List currently active ZTRE session policies
    POST   /api/v1/sigma/match           Match one event against loaded Sigma rules
    GET    /api/v1/sigma/rules           List loaded Sigma rules
    POST   /api/v1/threat-intel/stix/sync  Pull indicators from configured TAXII feed
    GET    /api/v1/sensors/ebpf/status   eBPF kernel entropy monitor mode + status
"""

import time
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from auth.manager import get_current_user, require_master
from rbac import require_permission, Perm

logger = logging.getLogger("ahras.api.v1")
audit_logger = logging.getLogger("ahras.audit")

# SECURITY: every route on this router required NO authentication at all until
# this fix — anyone who knew (or guessed) an endpoint path could submit fake
# events/logs, add IOCs, pull STIX feeds, or trigger ZTRE session changes with
# zero credentials. The router-level dependency below closes that: every
# /api/v1/* endpoint now requires, at minimum, a valid JWT (any role). State-
# changing / sensitive endpoints additionally require the MASTER role via an
# explicit `Depends(require_master)` parameter on that specific route (see
# submit_logs, submit_event, add_ioc, ztre_update_session, stix_sync below) —
# read-only / explain endpoints stay available to ANALYST.
api_router = APIRouter(tags=["External API v1"], dependencies=[Depends(get_current_user)])


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
    """Deprecated — kept only in case anything still imports this helper.
    Real enforcement now lives on api_router itself (dependencies=[...]) plus
    per-route Depends(require_master) on state-changing endpoints."""
    return Depends(get_current_user)


# ── POST /logs ────────────────────────────────────────────────────────────────
@api_router.post("/logs", summary="Submit raw logs for normalisation")
async def submit_logs(req: LogSubmission,
                      current_user: dict = Depends(require_permission(Perm.NORMALIZER_USE))):
    """
    Submit raw log entries from any source.
    AHRAS normalises them to the unified schema, then optionally
    passes them through the detection pipeline.

    Requires NORMALIZER_USE permission (write/ingest action — not granted to
    the legacy read-only ANALYST role; see rbac/permissions.py).

    Returns the normalised events + any alerts generated.
    """
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

    audit_logger.info(f"user={current_user.get('sub')} action=submit_logs count={len(req.logs)} alerts={len(alerts_generated)}")
    return {
        "submitted": len(req.logs),
        "normalised": len(normalised),
        "alerts_generated": alerts_generated,
        "events": normalised[:100],  # cap response at 100
    }


# ── POST /events ──────────────────────────────────────────────────────────────
@api_router.post("/events", summary="Submit pre-parsed events to risk engine")
async def submit_event(req: EventSubmission,
                        current_user: dict = Depends(require_permission(Perm.NORMALIZER_USE))):
    """
    Submit a pre-parsed event directly to the risk engine.
    Requires NORMALIZER_USE permission (write/ingest action).
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

    audit_logger.info(f"user={current_user.get('sub')} action=submit_event src_ip={req.src_ip} risk={result.risk_score_100} alert_id={alert_id}")
    return {
        "risk_score":  result.risk_score_100,
        "severity":    result.severity,
        "explanation": explanation,
        "alert_id":    alert_id,
    }


# ── POST /ioc ─────────────────────────────────────────────────────────────────
@api_router.post("/ioc", summary="Add Indicator of Compromise")
async def add_ioc(req: IOCSubmission,
                   current_user: dict = Depends(require_permission(Perm.IOC_WRITE))):
    """Add a new IOC to the AHRAS database. Immediately active for matching.
    Requires IOC_WRITE permission — not granted to the legacy read-only
    ANALYST role, only MASTER (and any future role explicitly given it)."""
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
            added_by=current_user.get("sub", "api"),
        )
        audit_logger.info(f"user={current_user.get('sub')} action=add_ioc indicator={req.indicator} type={req.ioc_type}")
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


# ── GET /features ─────────────────────────────────────────────────────────────
# One line per module so the API documents itself without reading the source.
# Keep this in sync with FEATURES.md — this is the canonical, live copy.
_FEATURE_MAP = {
    "sensors":            "Live packet capture and network flow generation.",
    "collectors":         "Pulls logs from OS and application sources (Windows, Linux, Apache).",
    "normalizer":         "Converts logs from different sources into a single unified event schema.",
    "feature_engineering": "Converts raw events into numeric features for the ML models.",
    "detection":          "Combines signature and ML anomaly detection into one hybrid engine.",
    "risk_engine":        "Combines detection signals into a single 0-100 risk score.",
    "historical_risk":    "Remembers past incidents per indicator so repeat offenders score higher.",
    "risk_explainer":     "Turns a raw risk score into a human-readable explanation.",
    "xai":                "Extended explainability for ML detections (feature attribution).",
    "adaptive_learning":  "Learns and tunes risk-scoring weights from analyst feedback.",
    "forecast":           "Predicts near-future risk trends from historical event data.",
    "mitre":              "Maps detected attack behavior to MITRE ATT&CK technique IDs.",
    "correlation":        "Links related alerts/events into a single incident narrative.",
    "graph":              "Builds an entity relationship graph (IPs, users, assets) for pivoting.",
    "uba":                "Baselines normal user activity and flags deviations.",
    "threat_intel":       "Looks up indicators against AbuseIPDB, VirusTotal, OTX, or local intel DB.",
    "ioc_management":     "Stores and matches Indicators of Compromise.",
    "threat_hunting":     "Proactive search across alerts, cases, IOCs, and threat intel.",
    "alerts":             "Creates, stores, and manages security alerts.",
    "case_management":    "Tracks investigation cases: creation, status, notes, linked alerts.",
    "forensics":          "Deeper investigation tooling for confirmed incidents.",
    "soar":               "Runs automated response playbooks on alerts.",
    "response_engine":    "Executes automated or analyst-triggered response actions.",
    "firewall":           "Optional IP blocking/allow-listing - disabled by default for safety.",
    "honeypot":           "Decoy SSH/FTP/HTTP services that lure and log attacker activity.",
    "asset_management":   "Tracks known hosts/assets and their criticality for risk weighting.",
    "event_management":   "Central event bus/store for all normalized security events.",
    "auth":               "Login, JWT tokens, and user identity.",
    "rbac":               "Role-based access control - 5 roles, granular permissions.",
    "api":                "External REST API layer (/api/v1) for integrations.",
    "dashboard":          "Web UI served at / - the analyst-facing view.",
    "reporting":          "Generates PDF/HTML incident and summary reports.",
    "evaluation":         "Loads benchmark datasets and scores detection accuracy.",
    "database":           "Persistence layer - MongoDB-backed, falls back to in-memory.",
    "maintenance":        "Backup, restore, cleanup, and delete utilities.",
    "graph.tgnn":         "Time-decayed graph embeddings scoring developing multi-hop attack paths.",
    "soar.copilot":       "LLM (or template) incident notes and exec summaries for playbook runs.",
    "adaptive_learning.ztre": "Zero-Trust engine: shrinks/revokes session access on risk spikes.",
    "sensors.ebpf_monitor": "Kernel-level (eBPF) file entropy monitoring for ransomware early warning.",
    "honeypot.deception_feedback": "Turns honeypot hits into Sigma rules + firewall blocks automatically.",
    "detection.sigma_engine": "Loads and matches community Sigma YAML detection rules.",
    "threat_intel.stix_ingestor": "Bulk-ingests STIX indicators from a TAXII 2.1 feed.",
}


@api_router.get("/features", summary="Self-describing list of every AHRAS module")
async def list_features():
    """
    Return a one-line description of every module in the system.
    Useful for onboarding, docs generation, or a UI 'what does this do' panel.
    Kept in sync with FEATURES.md.
    """
    return {
        "count": len(_FEATURE_MAP),
        "features": [
            {"module": name, "description": desc}
            for name, desc in _FEATURE_MAP.items()
        ],
    }


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


# ── Phase 2 additions: TGNN, LLM copilot, ZTRE, Sigma, STIX/TAXII, eBPF ─────────
# Each block is import-guarded so a missing optional dependency (e.g. PyYAML,
# numpy, or the honeypot/graph services not yet being wired up) degrades that
# one endpoint instead of breaking the whole API router.

class GraphPathRequest(BaseModel):
    source_ip: str = Field(..., description="Source IP to trace potential attack paths from")
    max_targets: int = Field(5, ge=1, le=20)
    max_hops: int = Field(4, ge=1, le=8)


@api_router.post("/graph/predict-paths", summary="Temporal-graph multi-hop attack path prediction")
async def predict_attack_paths(req: GraphPathRequest):
    """Score candidate multi-hop paths from a source IP toward high-value assets
    using time-decayed graph embeddings (see graph/tgnn.py)."""
    try:
        from graph.tgnn import tgnn_scorer
        mods = _get_modules()
        tgnn_scorer.threat_graph = mods.get("threat_graph") or getattr(tgnn_scorer, "threat_graph", None)
        preds = tgnn_scorer.predict_attack_paths(req.source_ip, req.max_targets, req.max_hops)
        return {"source_ip": req.source_ip, "predictions": [p.to_dict() for p in preds],
                "engine_stats": tgnn_scorer.stats()}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Temporal graph engine unavailable: {exc}")


class CopilotNarrativeRequest(BaseModel):
    playbook_run: dict = Field(..., description="A soar.engine.PlaybookRun.to_dict() payload")
    risk_score: Optional[float] = None
    extra_context: Optional[dict] = None


class AlertExplainerRequest(BaseModel):
    alert_name: str = Field(..., description="Human-readable alert title")
    risk_score: float = Field(..., ge=0, le=100)
    evidence: dict = Field(default_factory=dict, description="Evidence used by the risk engine")


class IncidentInvestigationRequest(BaseModel):
    src_ip: str = Field(..., description="Source IP under investigation")
    context: dict = Field(default_factory=dict, description="Alert, host, user, MITRE, and risk metadata")


class RiskIncreaseRequest(BaseModel):
    current_score: float = Field(..., ge=0, le=100)
    deltas: List[dict] = Field(default_factory=list, description="Ordered list of positive contributors")


class RiskTimelineRequest(BaseModel):
    values: List[float] = Field(default_factory=list, description="Risk values ordered over time")


@api_router.post("/soar/copilot/narrative", summary="LLM (or template) incident note + exec summary")
async def soar_copilot_narrative(req: CopilotNarrativeRequest):
    """Turns a playbook run into an analyst incident note and a plain-language
    exec summary. Uses a local LLM if AHRAS_LOCAL_LLM_URL is configured, else a
    safe deterministic template (see soar/copilot.py)."""
    from soar.copilot import generate_narrative, is_llm_configured
    narrative = generate_narrative(req.playbook_run, req.risk_score, req.extra_context)
    return {"incident_note": narrative.incident_note, "exec_summary": narrative.exec_summary,
            "generated_by": narrative.generated_by, "llm_configured": is_llm_configured()}


@api_router.post("/security/alert-explainer", summary="Explain why a risk score changed using the evidence chain (LLM narration if Ollama configured, else template)")
async def explain_alert(req: AlertExplainerRequest):
    from security_intelligence import SecurityIntelligenceEngine
    from utils.llm_client import is_llm_configured
    engine = SecurityIntelligenceEngine()
    mods = _get_modules()
    live_evidence = engine.build_live_alert_evidence(
        src_ip=req.evidence.get("src_ip", "unknown"),
        alert_name=req.alert_name,
        risk_score=req.risk_score,
        hist_risk=mods.get("hist_risk"),
        threat_graph=getattr(__import__("main", fromlist=["threat_graph"]), "threat_graph", None),
        alert_mgr=mods.get("alert_mgr"),
        extra=req.evidence,
    )
    result = engine.alert_explainer(req.alert_name, req.risk_score, live_evidence)
    result["llm_configured"] = is_llm_configured()
    return result


@api_router.post("/security/investigate-incident", summary="Create a structured incident investigation summary (LLM narration if Ollama configured, else template)")
async def investigate_incident(req: IncidentInvestigationRequest):
    from security_intelligence import SecurityIntelligenceEngine
    from utils.llm_client import is_llm_configured
    engine = SecurityIntelligenceEngine()
    mods = _get_modules()
    graph = getattr(__import__("main", fromlist=["threat_graph"]), "threat_graph", None)
    history = mods.get("hist_risk")
    alert_mgr = mods.get("alert_mgr")

    related_ips = []
    if graph is not None:
        try:
            related_ips = (graph.blast_radius(req.src_ip, hops=2) or {}).get("related_ips", [])
        except Exception:
            related_ips = []

    historic = {}
    if history is not None:
        try:
            historic = history.get_history_dict(req.src_ip, "ip") or {}
        except Exception:
            historic = {}

    alerts = []
    if alert_mgr is not None:
        try:
            alerts = [a for a in (alert_mgr.list_alerts(limit=20) or []) if a.get("target_ip") == req.src_ip]
        except Exception:
            alerts = []

    ctx = dict(req.context)
    ctx.setdefault("related_ips", related_ips)
    ctx.setdefault("alerts", [a.get("title", "alert") for a in alerts])
    ctx.setdefault("historical_incidents", historic.get("incident_count", 0))
    result = engine.investigate_incident(req.src_ip, ctx)
    result["llm_configured"] = is_llm_configured()
    return result


@api_router.post("/security/risk-increase", summary="Explain why risk increased and show additive contributors")
async def explain_risk_increase(req: RiskIncreaseRequest):
    from security_intelligence import SecurityIntelligenceEngine
    engine = SecurityIntelligenceEngine()
    return engine.explain_risk_increase(req.current_score, req.deltas)


@api_router.post("/security/risk-timeline", summary="Return risk velocity, acceleration, and threat trajectory")
async def risk_timeline(req: RiskTimelineRequest):
    from security_intelligence import SecurityIntelligenceEngine
    engine = SecurityIntelligenceEngine()
    return engine.risk_timeline(req.values)


class RiskTrajectoryRequest(BaseModel):
    src_ip: str = Field(..., description="The source IP whose risk trajectory will be measured")


class CounterfactualRequest(BaseModel):
    src_ip: str = Field(..., description="Source IP to evaluate")
    blocked_step: str = Field(..., description="Step that would have been blocked")


@api_router.post("/security/live-risk-timeline", summary="Risk trajectory generated from live AHRAS history and graph context")
async def live_risk_timeline(req: RiskTrajectoryRequest):
    from security_intelligence import SecurityIntelligenceEngine
    engine = SecurityIntelligenceEngine()
    mods = _get_modules()
    graph = getattr(__import__("main", fromlist=["threat_graph"]), "threat_graph", None)
    return engine.build_live_risk_timeline(req.src_ip, mods.get("hist_risk"), graph)


@api_router.post("/security/counterfactual-risk", summary="Estimate the impact if a blocking step failed")
async def counterfactual_risk(req: CounterfactualRequest):
    from security_intelligence import SecurityIntelligenceEngine
    engine = SecurityIntelligenceEngine()
    graph = getattr(__import__("main", fromlist=["threat_graph"]), "threat_graph", None)
    return engine.counterfactual_risk_analysis(req.src_ip, req.blocked_step, graph)


# ════════════════════════════════════════════════════════════════════════════
# ENHANCED SECURITY INTELLIGENCE — Real threat analysis with deep integration
# ════════════════════════════════════════════════════════════════════════════

class ConfidenceScoredEvidenceRequest(BaseModel):
    src_ip: str = Field(..., description="Source IP to analyze")
    risk_score: float = Field(..., ge=0, le=100)
    failed_logins: int = Field(0, ge=0)
    successful_login: bool = False
    historical_incidents: int = Field(0, ge=0)
    ioc_match: bool = False
    graph_proximity: str = Field("low", description="low | high | critical")
    mitre: List[str] = Field(default_factory=list)


class AssetImpactRequest(BaseModel):
    src_ip: str = Field(..., description="Source IP to assess impact for")


class ThreatPatternRequest(BaseModel):
    src_ip: str = Field(..., description="Source IP")
    attack_type: str = Field(..., description="Type of attack detected")
    severity: str = Field(..., description="CRITICAL | HIGH | MEDIUM | LOW")


class RiskComponentDeepDiveRequest(BaseModel):
    src_ip: str = Field(..., description="Source IP")
    risk_score: float = Field(..., ge=0, le=100)
    raw_components: Optional[dict] = Field(None, description="Risk breakdown by component")


class IncidentCorrelationRequest(BaseModel):
    src_ip: str = Field(..., description="Source IP")
    attack_type: str = Field(..., description="Type of current attack")


class AutomatedResponseRequest(BaseModel):
    src_ip: str = Field(..., description="Source IP")
    severity: str = Field(..., description="CRITICAL | HIGH | MEDIUM | LOW")
    risk_score: float = Field(..., ge=0, le=100)
    attack_type: str = Field(..., description="Attack classification")
    asset_count: int = Field(0, ge=0, description="Number of assets at risk")


@api_router.post("/security/evidence-chain", summary="Confidence-scored evidence chain with MITRE mapping")
async def evidence_chain(req: ConfidenceScoredEvidenceRequest):
    """Build structured evidence where each piece is scored for confidence and
    mapped to MITRE ATT&CK techniques. Shows what we know and how sure we are."""
    from security_intelligence import SecurityIntelligenceEngine
    engine = SecurityIntelligenceEngine()
    context = {
        "failed_logins": req.failed_logins,
        "successful_login": req.successful_login,
        "historical_incidents": req.historical_incidents,
        "ioc_match": req.ioc_match,
        "graph_proximity": req.graph_proximity,
    }
    return engine.confidence_scored_evidence_chain(req.src_ip, context, req.risk_score, req.mitre)


@api_router.post("/security/asset-impact", summary="Which critical assets are at risk from this source?")
async def asset_impact(req: AssetImpactRequest):
    """Assess and rank critical assets that this source poses a threat to."""
    from security_intelligence import SecurityIntelligenceEngine
    engine = SecurityIntelligenceEngine()
    mods = _get_modules()
    graph = getattr(__import__("main", fromlist=["threat_graph"]), "threat_graph", None)
    return engine.asset_impact_assessment(req.src_ip, graph, mods.get("context"))


@api_router.post("/security/threat-pattern", summary="Generate tailored recommendations based on threat type")
async def threat_pattern(req: ThreatPatternRequest):
    """Based on the attack type and severity, recommend specific containment,
    remediation, and preventive measures."""
    from security_intelligence import SecurityIntelligenceEngine
    engine = SecurityIntelligenceEngine()
    return engine.threat_pattern_recommendations(req.src_ip, req.attack_type, req.severity)


@api_router.post("/security/risk-components", summary="Deep-dive breakdown of risk score factors")
async def risk_components(req: RiskComponentDeepDiveRequest):
    """Show exactly which detection/risk components contributed to the final risk score
    and how much each one influenced the decision."""
    from security_intelligence import SecurityIntelligenceEngine
    engine = SecurityIntelligenceEngine()
    return engine.risk_component_deep_dive(req.src_ip, req.risk_score, req.raw_components)


@api_router.post("/security/incident-correlation", summary="Find similar past incidents for context")
async def incident_correlation(req: IncidentCorrelationRequest):
    """Look up historical incidents from this source to determine if this is a
    known repeat offender or if this attack pattern has been seen before."""
    from security_intelligence import SecurityIntelligenceEngine
    engine = SecurityIntelligenceEngine()
    mods = _get_modules()
    return engine.live_incident_correlation(req.src_ip, req.attack_type, mods.get("hist_risk"))


@api_router.post("/security/response-automation", summary="Automated response playbook recommendations")
async def response_automation(req: AutomatedResponseRequest):
    """Recommend which security playbooks to execute and what automation level
    to use (observe, monitored, defensive, aggressive) based on threat severity."""
    from security_intelligence import SecurityIntelligenceEngine
    engine = SecurityIntelligenceEngine()
    return engine.automated_response_recommendations(
        req.src_ip, req.severity, req.risk_score, req.attack_type, req.asset_count
    )


class ZTRESessionRequest(BaseModel):
    session_id: str
    subject: str = Field(..., description="Username or source IP tied to this session")
    risk_score: float = Field(..., ge=0, le=100)


@api_router.post("/ztre/session", summary="Continuous Zero-Trust session risk re-evaluation")
async def ztre_update_session(req: ZTRESessionRequest,
                               current_user: dict = Depends(require_master)):
    """Feed a fresh risk score for an active session; returns the access scope
    and TTL that session should immediately be constrained to (see adaptive_learning/ztre.py).
    Master-only: this can revoke/restrict any user's live session — a control-
    plane action, not a read/query."""
    from adaptive_learning.ztre import ztre_engine
    policy = ztre_engine.update_session(req.session_id, req.subject, req.risk_score)
    audit_logger.info(f"user={current_user.get('sub')} action=ztre_update_session subject={req.subject} risk={req.risk_score} decision={policy.to_dict().get('scope')}")
    return policy.to_dict()


@api_router.get("/ztre/sessions", summary="List currently active ZTRE session policies")
async def ztre_list_sessions():
    from adaptive_learning.ztre import ztre_engine
    return {"active_sessions": ztre_engine.active_sessions()}


class SigmaMatchRequest(BaseModel):
    event: dict = Field(..., description="Normalized event fields to test against loaded Sigma rules")


@api_router.post("/sigma/match", summary="Match one event against loaded Sigma rules")
async def sigma_match(req: SigmaMatchRequest):
    from detection.sigma_engine.engine import sigma_engine
    matches = sigma_engine.match(req.event)
    return {"matched": len(matches) > 0, "matches": [m.to_dict() for m in matches]}


@api_router.get("/sigma/rules", summary="List loaded Sigma rules")
async def sigma_rules():
    from detection.sigma_engine.engine import sigma_engine
    return {"stats": sigma_engine.stats(),
            "rules": [{"rule_id": r.rule_id, "title": r.title, "level": r.level, "tags": r.tags}
                      for r in sigma_engine.rules.values()]}


class STIXSyncRequest(BaseModel):
    limit: int = Field(500, ge=1, le=5000)


@api_router.post("/threat-intel/stix/sync", summary="Pull indicators from configured TAXII feed")
async def stix_sync(req: STIXSyncRequest,
                     current_user: dict = Depends(require_permission(Perm.TI_ENRICH))):
    """Requires AHRAS_STIX_TAXII_URL + AHRAS_STIX_COLLECTION_ID to be set;
    see threat_intel/stix_ingestor.py. Returns [] with a status note if unconfigured.
    Requires TI_ENRICH permission — this triggers live outbound network calls
    to an external feed, not granted to the legacy read-only ANALYST role."""
    from threat_intel.stix_ingestor import stix_ingestor
    mods = _get_modules()
    stix_ingestor.ioc_mgr = mods.get("ioc_mgr") or stix_ingestor.ioc_mgr
    ingested = stix_ingestor.sync(limit=req.limit)
    audit_logger.info(f"user={current_user.get('sub')} action=stix_sync ingested={len(ingested)}")
    return {"status": stix_ingestor.status(), "ingested": [i.to_dict() for i in ingested]}


@api_router.get("/sensors/ebpf/status", summary="eBPF kernel entropy monitor mode + status")
async def ebpf_status():
    """Reports whether the ransomware early-warning monitor is running real
    kernel-level eBPF hooks or the portable polling fallback (see sensors/ebpf_monitor.py)."""
    mods = _get_modules()
    monitor = mods.get("ebpf_monitor")
    if monitor is None:
        return {"running": False, "note": "eBPF monitor not started for this process"}
    return monitor.status()
