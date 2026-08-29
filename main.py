"""AHRAS v4.0 — Complete SOC/SIEM Platform
Merges best ML from working version + all v3 features + 5 new modules:
  Asset Management · UBA · SOAR · Maintenance API · Fixed Risk Engine
"""
import os, sys, time, queue, threading, logging, json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List

import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

sys.path.insert(0, os.path.dirname(__file__))

from config import config
from auth.manager import AuthManager, get_auth_manager, get_current_user, require_master, UserRole
from firewall.manager import FirewallManager
from alerts.manager import AlertReportManager
from detection.ransomware_engine import RansomwareDetector
from detection.virus_engine import VirusDetector
from sensors import PacketSniffer, FlowGenerator
from detection import HybridDetectionEngine
from risk_engine.risk_scorer import RiskEngine
from event_management import EventManager
from utils import EnrichmentService

# v3 modules
from mitre import MitreMapper
from threat_intel import ThreatIntelManager
from ioc_management import IOCManager
from case_management import CaseManager
from correlation import CorrelationEngine
from honeypot import HoneypotManager
from reporting import ReportGenerator

# v4 new modules
from asset_management import AssetManager
from uba import UBAEngine
from adaptive_learning import AdaptiveWeightLearner
from adaptive_learning.weight_learner import FeedbackSample
from forecast import AttackPredictor
from graph import ThreatGraph
from xai import ExtendedExplainer
from soar import SOAREngine
from threat_hunting import ThreatHunter
from forensics import ForensicsManager
from normalizer import LogNormalizer
from risk_explainer import RiskExplainer
from collectors import WindowsLogCollector, LinuxLogCollector, ApacheLogCollector
from rbac import Perm, Role, require_permission, require_role, require_admin, role_summary
from historical_risk import HistoricalRiskEngine
from security_intelligence import SecurityIntelligenceEngine
from api import api_router
from database import db_connect, db_health, is_connected as db_is_connected

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger("ahras.api")

# ── MongoDB connection (before singletons so repos are ready) ──────────────────
_mongo_connected = db_connect(
    uri=config.MONGO_URI,
    db_name=config.MONGO_DB,
)
if _mongo_connected:
    logger.info("✓ MongoDB connected — data will persist across restarts")
else:
    logger.warning("⚠ MongoDB unavailable — running in memory-only mode (data lost on restart)")

# ── Singletons ─────────────────────────────────────────────────────────────────
auth_mgr     = get_auth_manager()
firewall     = FirewallManager()
alert_mgr    = AlertReportManager()
mitre_map    = MitreMapper()
threat_intel = ThreatIntelManager(
    abuseipdb_key=os.getenv("ABUSEIPDB_KEY",""),
    virustotal_key=os.getenv("VIRUSTOTAL_KEY",""),
    otx_key=os.getenv("OTX_KEY",""),
)
ioc_mgr     = IOCManager()
case_mgr    = CaseManager()
corr_engine = CorrelationEngine()
honeypot    = HoneypotManager(
    ssh_port=int(os.getenv("HONEYPOT_SSH_PORT","2222")),
    ftp_port=int(os.getenv("HONEYPOT_FTP_PORT","2121")),
    http_port=int(os.getenv("HONEYPOT_HTTP_PORT","8081")),
)
report_gen  = ReportGenerator()
asset_mgr   = AssetManager()
uba_engine  = UBAEngine()
soar_engine = SOAREngine()

# ── New Modules ───────────────────────────────────────────────────────────────
threat_hunter   = ThreatHunter()
forensics_mgr   = ForensicsManager()
log_normalizer  = LogNormalizer()
risk_explainer       = RiskExplainer()
hist_risk            = HistoricalRiskEngine()
security_intel       = SecurityIntelligenceEngine()
predictor            = AttackPredictor(horizon=5)
threat_graph         = ThreatGraph()
xai_explainer        = ExtendedExplainer()
_explanation_history: list = []   # rolling buffer for feature_importance batch analysis
_EXPLANATION_HISTORY_MAXLEN = 500

_pkt_q  = queue.Queue(maxsize=5000)
_flow_q = queue.Queue(maxsize=2000)
sniffer  = PacketSniffer(_pkt_q)
flow_gen = FlowGenerator(_pkt_q, _flow_q)
detector = HybridDetectionEngine()
risk_eng = RiskEngine()
risk_eng.set_asset_manager(asset_mgr)   # inject asset manager

try:
    from database import get_collection
    _aw_col = get_collection("adaptive_weights")
except Exception:
    _aw_col = None
weight_learner = AdaptiveWeightLearner(mongo_collection=_aw_col)
risk_eng.set_adaptive_learner(weight_learner)

# In-memory cache: src_ip -> last RiskResult.raw_components/risk seen for that IP
# Used to recover the feature vector when a case is closed, since cases
# reference an IP but not the exact RiskResult that triggered them.
_risk_feedback_cache: dict = {}
_RISK_CACHE_MAXLEN = 2000
evt_mgr  = EventManager()
enricher = EnrichmentService()

def _ransom_notify(a): alert_mgr._push_notification("RANSOMWARE", a.alert_id, a.details)
def _virus_notify(a):  alert_mgr._push_notification("VIRUS", a.alert_id, a.threat_name)

ransomware = RansomwareDetector(on_alert=_ransom_notify)
virus_det  = VirusDetector(on_alert=_virus_notify)

# ── FastAPI app ────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app):
    # startup
    sniffer.start(); flow_gen.start()
    threading.Thread(target=_analysis_worker, daemon=True).start()
    ransomware.start_monitoring(); virus_det.start_background_scan()
    honeypot.start()
    logger.info("AHRAS v4.0 fully operational")
    yield
    # shutdown
    sniffer.stop(); flow_gen.stop(); honeypot.stop()

app = FastAPI(title="AHRAS SOC v4.0", version="4.0.0", lifespan=lifespan)

# CORS — SECURITY: wildcard ("*") origins let ANY website's JavaScript call
# this API using a logged-in analyst's browser session (CSRF-style abuse of
# the dashboard's own cookies/headers). Set ALLOWED_ORIGINS in .env to a
# comma-separated list of real frontend origins for anything beyond local
# development, e.g. ALLOWED_ORIGINS=https://ahras.yourcompany.com
_allowed_origins_env = os.getenv("ALLOWED_ORIGINS", "").strip()
if _allowed_origins_env:
    _cors_origins = [o.strip() for o in _allowed_origins_env.split(",") if o.strip()]
elif config.DEBUG:
    _cors_origins = ["http://localhost:8000", "http://127.0.0.1:8000",
                      "http://localhost:3000", "http://127.0.0.1:3000"]
    logger.warning(
        "ALLOWED_ORIGINS not set — defaulting to localhost-only CORS in DEBUG "
        "mode. Set ALLOWED_ORIGINS explicitly before deploying anywhere else."
    )
else:
    _cors_origins = []
    logger.warning(
        "ALLOWED_ORIGINS not set and DEBUG=false — CORS will reject all "
        "cross-origin browser requests until you set it in .env."
    )
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount external API v1 (every route below requires a valid JWT at minimum —
# see api/router.py's api_router = APIRouter(dependencies=[Depends(get_current_user)]))
app.include_router(api_router, prefix="/api/v1")

# Wire ThreatHunter to all data sources
threat_hunter.inject(
    alert_mgr=alert_mgr, case_mgr=case_mgr,
    threat_intel=threat_intel, ioc_mgr=ioc_mgr,
    mitre=mitre_map, risk_engine=risk_eng,
)

# Wire up SOAR
soar_engine.inject(firewall=firewall, case_mgr=case_mgr, ioc_mgr=ioc_mgr,
                   alert_mgr=alert_mgr, report_gen=report_gen, threat_graph=threat_graph)

def _honeypot_hit(hit):
    alert_mgr._push_notification("HONEYPOT", hit.hit_id,
        f"{hit.service} honeypot hit from {hit.src_ip}: {hit.data[:80]}")
    soar_engine.on_honeypot_hit(hit)

honeypot.on_hit(_honeypot_hit)

def _analysis_worker():
    logger.info("Analysis worker v6 started")
    while True:
        try:
            flow = _flow_q.get(timeout=1.0)
        except queue.Empty:
            continue
        try:
            det  = detector.analyse(flow)
            # Inject history boost before risk scoring
            det_dict = det.__dict__ if hasattr(det, "__dict__") else det
            src_ip = getattr(det, "src_ip", det_dict.get("src_ip", ""))
            history_boost = hist_risk.get_boost(src_ip) if src_ip else 0.0
            if hasattr(det, "src_ip"):
                try: det.history_boost = history_boost
                except: pass
            # Enrich BEFORE risk scoring (not after) so the risk engine's trust
            # check can use the resolved organization name -- the same one the
            # dashboard displays -- instead of doing its own separate, less
            # reliable reverse-DNS lookup with no knowledge of who the IP is.
            info = enricher.enrich(src_ip) if src_ip else {}
            if hasattr(det, "organization"):
                try: det.organization = info.get("organization", "")
                except Exception: pass
            risk = risk_eng.evaluate(det)
            ev   = evt_mgr.store(det, risk, enrichment=info)

            # Cache feature vector for adaptive learning feedback (keyed by src_ip,
            # overwritten on each new event so case closure grabs the most recent
            # detection that likely caused the case to be opened)
            if risk.risk_score_100 >= 20 and ev.src_ip:  # only cache non-trivial detections
                if len(_risk_feedback_cache) > _RISK_CACHE_MAXLEN:
                    _risk_feedback_cache.clear()
                _risk_feedback_cache[ev.src_ip] = {
                    "components": risk.raw_components,
                    "predicted_risk": risk.risk_score_100,
                    "timestamp": time.time(),
                }

            # Record in history engine
            hist_risk.record_event({
                "src_ip": ev.src_ip,
                "attack_type": getattr(det, "attack_type", "Normal"),
                "severity": risk.severity,
            }, risk.risk_score_100)

            # Was: `risk.overall >= firewall.AUTO_BLOCK_RISK` -- overall is
            # capped at 1.0 and AUTO_BLOCK_RISK defaults to 90.0 (0-100
            # scale, see config/settings.py), so that comparison could NEVER
            # be true regardless of severity: auto-block was silently dead
            # no matter what AUTO_BLOCK_ENABLED/AUTO_BLOCK_RISK_THRESHOLD
            # were set to. Fixed 27-08-26: use risk_score_100 (the
            # unambiguous 0-100 field) via the firewall's own dedicated
            # evaluate_auto_block(), which already existed but wasn't
            # actually being called from here.
            firewall.evaluate_auto_block(
                ev.src_ip, risk.risk_score_100,
                reason=f"auto-block risk={risk.risk_score_100:.1f}",
            )

            # Record asset alert
            if det.attack_type != "Normal":
                asset_mgr.record_alert(ev.src_ip)

            if det.attack_type != "Normal":
                mitre_result = mitre_map.map(det.attack_type)
                ioc_hit      = ioc_mgr.match_ip(ev.src_ip)
                ti_result    = threat_intel.check_ip(ev.src_ip)
                ev_dict      = ev.to_dict()
                if mitre_result:
                    ev_dict["mitre_technique"] = mitre_result.technique_id
                    ev_dict["mitre_tactic"]    = mitre_result.tactic
                if ioc_hit:
                    ev_dict["ioc_match"] = True
                    ev_dict["ioc_threat_level"] = ioc_hit.threat_level.value
                    soar_engine.on_ioc_match(ev.src_ip, ioc_hit, ev_dict)
                    threat_graph.ingest_ioc_match(ev.src_ip, ioc_hit.indicator, ioc_hit.ioc_type.value if hasattr(ioc_hit.ioc_type,"value") else str(ioc_hit.ioc_type))
                if ti_result.is_malicious:
                    ev_dict["ti_malicious"]   = True
                    ev_dict["ti_confidence"]  = ti_result.confidence

                threat_graph.ingest_event(ev_dict)

                # Feed live explanation history for global feature importance
                # (only events that actually scored something, to keep the
                # buffer meaningful rather than full of zero-score noise)
                if risk.risk_score_100 >= 10:
                    try:
                        exp = risk_explainer.explain(risk).to_dict()
                        _explanation_history.append(exp)
                        if len(_explanation_history) > _EXPLANATION_HISTORY_MAXLEN:
                            _explanation_history.pop(0)
                    except Exception:
                        pass

                incident = corr_engine.ingest(ev_dict)
                if incident:
                    alert_mgr._push_notification("CORRELATION", incident.incident_id,
                        f"{incident.rule.name} — {incident.src_ip}")
                    soar_engine.on_correlation_incident(incident.to_dict())
                    # Record incident in history
                    hist_risk.record_incident(ev.src_ip)

                # SOAR high-risk response
                if risk.risk_score_100 >= 70:
                    # Don't SOAR-trigger on private IPs for generic anomaly — only real attacks
                    from risk_engine.risk_scorer import _is_private
                    attack = ev_dict.get("attack_type", "Normal")
                    genuine_attack = attack not in ("Normal", "Anomalous Behaviour")
                    if not _is_private(ev.src_ip) or genuine_attack:
                        soar_engine.on_high_risk(ev_dict, risk)
                    # Record alert in history
                    hist_risk.record_alert(ev.src_ip)

        except Exception as e:
            logger.error(f"Analysis error: {e}", exc_info=True)

# ── Pydantic models ────────────────────────────────────────────────────────────
class BlockIPReq(BaseModel):    ip: str; reason: str = ""
class BlockPortReq(BaseModel):  port: int; protocol: str = "tcp"; reason: str = ""
class ToggleReq(BaseModel):     feature: str; enabled: bool
class WLReq(BaseModel):         ip: str
class AlertSubmitReq(BaseModel):
    title: str; description: str; priority: str = "MEDIUM"
    target_ip: str = ""; attack_type: str = ""; event_ids: List[str] = []
class ReportSubmitReq(BaseModel):
    title: str; summary: str; findings: str; recommendations: str
    severity: str = "MEDIUM"; affected_ips: List[str] = []; event_ids: List[str] = []
class ReviewReq(BaseModel):     status: str; notes: str = ""; action: str = ""
class UserCreateReq(BaseModel):
    username: str; password: str; role: str; full_name: str = ""; email: str = ""
class IOCCreateReq(BaseModel):
    indicator: str; ioc_type: str; threat_level: str; description: str
    tags: List[str] = []; source: str = "manual"; mitre_technique: str = ""
class CaseCreateReq(BaseModel):
    title: str; description: str; priority: str = "MEDIUM"
    attack_type: str = ""; affected_ips: List[str] = []
    event_ids: List[str] = []; alert_ids: List[str] = []
    mitre_technique: str = ""; mitre_tactic: str = ""; tags: List[str] = []
class CaseNoteReq(BaseModel):   content: str; note_type: str = "note"
class CaseAssignReq(BaseModel): assigned_to: str
class CaseStatusReq(BaseModel): status: str; note: str = ""
class AdaptiveFeedbackReq(BaseModel):
    src_ip: str; label: int  # 1=true positive, 0=false positive
    components: dict = {}    # {"signature":0-1,"anomaly":0-1,"density":0-1,"drift_rate":0-1}
    predicted_risk: float = 0.0
class CaseResolveReq(BaseModel):resolution: str
class CaseCloseReq(BaseModel):  notes: str = ""
class ThreatHuntReq(BaseModel): query: str; query_type: str = "ip"
class AssetCreateReq(BaseModel):
    name: str; ip: str; asset_type: str; criticality: int
    owner: str = ""; description: str = ""; tags: List[str] = []; os: str = ""; location: str = ""
class ClearDataReq(BaseModel):
    target: str = "events"  # events|alerts|correlations|cases|iocs|history|logs|reports|models|all

# ── Auth ───────────────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends()):
    from auth.manager import AccountLockedError
    ip = request.client.host if request.client else "unknown"
    try:
        token = auth_mgr.authenticate(form.username, form.password, ip)
    except AccountLockedError as e:
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed login attempts. Try again in {e.retry_after_secs}s.",
        )
    if not token: raise HTTPException(401, "Invalid credentials")
    user = auth_mgr.get_user(form.username)
    # UBA: record login
    uba_engine.record_login(form.username, ip)
    return {"access_token": token, "token_type": "bearer",
            "role": user.role.value, "username": form.username,
            "must_change_password": user.must_change_password}

class ChangePasswordReq(BaseModel):
    old_password: str
    new_password: str

@app.post("/api/auth/change-password")
async def change_password(req: ChangePasswordReq, cu: dict = Depends(get_current_user)):
    if len(req.new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    ok = auth_mgr.change_password(cu["sub"], req.old_password, req.new_password)
    if not ok:
        raise HTTPException(401, "Current password is incorrect")
    return {"success": True, "message": "Password changed"}

@app.post("/api/auth/logout")
async def logout(cu: dict = Depends(get_current_user)):
    auth_mgr.logout(cu.get("session_id","")); return {"message": "Logged out"}

@app.get("/api/auth/me")
async def me(cu: dict = Depends(get_current_user)):
    u = auth_mgr.get_user(cu["sub"]); return u.to_dict() if u else {}

# ── Master: users ──────────────────────────────────────────────────────────────
@app.get("/api/master/users")
async def list_users(m: dict = Depends(require_master)):
    return {"users": auth_mgr.list_users()}

@app.post("/api/master/users")
async def create_user(req: UserCreateReq, m: dict = Depends(require_master)):
    u = auth_mgr.create_user(req.username, req.password, UserRole(req.role.lower()), req.full_name, req.email)
    return u.to_dict()

@app.get("/api/master/login-history")
async def login_history(limit: int = 50, m: dict = Depends(require_master)):
    return {"history": auth_mgr.login_history(limit), "active": auth_mgr.active_sessions()}

# ── Events & Stats ─────────────────────────────────────────────────────────────
@app.get("/api/events")
async def get_events(limit: int = 50, severity: str = None, _: dict = Depends(get_current_user)):
    evts = evt_mgr.recent_events(min(limit, 200))
    if severity and severity.upper() != "ALL":
        evts = [e for e in evts if e.get("severity") == severity.upper()]
    for e in evts:
        e["blocked"] = firewall.is_blocked(e.get("src_ip",""))
        attack = e.get("attack_type","Normal")
        if attack != "Normal":
            mr = mitre_map.map(attack)
            if mr:
                e["mitre_technique"] = mr.technique_id
                e["mitre_technique_name"] = mr.technique_name
                e["mitre_tactic"] = mr.tactic
                e["mitre_url"] = mr.url
        # Attach asset info
        asset = asset_mgr.get_by_ip(e.get("src_ip",""))
        if asset: e["asset_name"] = asset.name; e["asset_criticality"] = asset.criticality
    return {"events": evts, "total": evt_mgr.total_count()}

@app.get("/api/capture-status")
async def capture_status(_: dict = Depends(get_current_user)):
    """Tells the UI whether real packet capture is actually working, and why
    not if it isn't, instead of the live feed just silently staying empty."""
    from sensors.packet_sniffer import SCAPY_AVAILABLE
    import os, ctypes
    is_admin = None
    try:
        if os.name == "nt":
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            is_admin = os.geteuid() == 0
    except Exception:
        pass
    ifaces = []
    try:
        if SCAPY_AVAILABLE:
            from scapy.all import get_if_list
            ifaces = get_if_list()
    except Exception:
        pass
    return {
        "scapy_available": SCAPY_AVAILABLE,
        "running_as_admin_or_root": is_admin,
        "interface_configured": sniffer.interface,
        "interfaces_detected": ifaces,
        "packets_captured": sniffer.captured,
        "packets_dropped": sniffer.dropped,
        "flows_emitted": flow_gen.emitted,
        "synthetic_fallback_enabled": config.SYNTHETIC_FALLBACK_ENABLED,
        "status": "capturing" if sniffer.captured > 0 else "no_packets_yet",
    }

@app.get("/api/stats")
async def get_stats(_: dict = Depends(get_current_user)):
    evts = evt_mgr.recent_events(500)
    attacker_counts = {}; country_counts = {}; port_counts = {}
    for e in evts:
        ip=e.get("src_ip",""); country=e.get("country","Unknown"); port=e.get("dst_port",0)
        if ip: attacker_counts[ip]=attacker_counts.get(ip,0)+1
        if country and country!="Unknown": country_counts[country]=country_counts.get(country,0)+1
        if port: port_counts[str(port)]=port_counts.get(str(port),0)+1
    return {
        "total_events":       evt_mgr.total_count(),
        "severity_counts":    evt_mgr.severity_counts(),
        "attack_type_counts": evt_mgr.attack_type_counts(),
        "protocol_counts":    evt_mgr.protocol_counts(),
        "risk_trend":         evt_mgr.risk_trend(30),
        "top_attackers":      [{"ip":ip,"count":c} for ip,c in sorted(attacker_counts.items(),key=lambda x:x[1],reverse=True)[:10]],
        "top_countries":      [{"country":c,"count":n} for c,n in sorted(country_counts.items(),key=lambda x:x[1],reverse=True)[:10]],
        "top_ports":          [{"port":p,"count":n} for p,n in sorted(port_counts.items(),key=lambda x:x[1],reverse=True)[:10]],
        "correlation_stats":  corr_engine.stats(),
        "honeypot_stats":     honeypot.stats(),
        "ioc_stats":          ioc_mgr.stats(),
        "case_stats":         case_mgr.stats(),
        "threat_intel_stats": threat_intel.stats(),
        "asset_stats":        asset_mgr.stats(),
        "uba_stats":          uba_engine.stats(),
        "soar_stats":         soar_engine.stats(),
    }

# ── AI Summarizer (plain-English digest for non-security readers) ───────────
@app.get("/api/summary/plain-english")
async def plain_english_dashboard_summary(_: dict = Depends(get_current_user)):
    """
    Turns the current SOC state into a short digest a non-technical person can
    read: what's happening, why, and whether they need to do anything.
    Always returns a deterministic summary; adds a local-LLM-narrated version
    (see AHRAS_LOCAL_LLM_URL) on top when one is configured, else 'generated_by'
    is 'template' and 'llm_narrative' is null — both cases are safe to render.
    """
    from security_intelligence import SecurityIntelligenceEngine

    sev = evt_mgr.severity_counts()
    trend = evt_mgr.risk_trend(10)
    current_risk = float(trend[-1]["risk"]) if trend else 0.0
    total_alerts = sum(sev.values())

    evts = evt_mgr.recent_events(200)
    attacker_counts: dict = {}
    for e in evts:
        ip = e.get("src_ip", "")
        if ip:
            attacker_counts[ip] = attacker_counts.get(ip, 0) + 1
    top_sources = [ip for ip, _ in sorted(attacker_counts.items(), key=lambda x: x[1], reverse=True)[:3]]

    try:
        blocked = len(firewall.blocked_ips_list())
    except Exception:
        blocked = 0

    overview = {
        "total_alerts": total_alerts,
        "critical_alerts": sev.get("CRITICAL", 0),
        "high_alerts": sev.get("HIGH", 0),
        "current_risk": current_risk,
        "top_threat_sources": top_sources,
        "blocked_ips": blocked,
    }

    engine = SecurityIntelligenceEngine()
    return engine.plain_english_summary(overview)


# ── MITRE ──────────────────────────────────────────────────────────────────────
@app.get("/api/mitre/map/{attack_type}")
async def mitre_lookup(attack_type: str, _: dict = Depends(get_current_user)):
    r = mitre_map.map(attack_type); return r.to_dict() if r else {"error":"No mapping found"}

@app.get("/api/mitre/all")
async def mitre_all(_: dict = Depends(get_current_user)):
    return {"techniques": mitre_map.all_techniques(), "by_tactic": mitre_map.techniques_by_tactic()}

# ── Threat Intel ───────────────────────────────────────────────────────────────
@app.get("/api/threat-intel/ip/{ip}")
async def ti_ip(ip: str, _: dict = Depends(get_current_user)):
    return threat_intel.check_ip(ip).to_dict()

@app.get("/api/threat-intel/domain/{domain}")
async def ti_domain(domain: str, _: dict = Depends(get_current_user)):
    return threat_intel.check_domain(domain).to_dict()

@app.get("/api/threat-intel/hash/{file_hash}")
async def ti_hash(file_hash: str, _: dict = Depends(get_current_user)):
    return threat_intel.check_hash(file_hash).to_dict()

@app.get("/api/threat-intel/stats")
async def ti_stats(_: dict = Depends(get_current_user)):
    return threat_intel.stats()

# ── IOC ────────────────────────────────────────────────────────────────────────
@app.get("/api/ioc")
async def list_iocs(ioc_type: str = None, _: dict = Depends(get_current_user)):
    return {"iocs": ioc_mgr.list_iocs(ioc_type), "stats": ioc_mgr.stats()}

@app.post("/api/ioc")
async def add_ioc(req: IOCCreateReq, cu: dict = Depends(get_current_user)):
    return ioc_mgr.add_ioc(req.indicator, req.ioc_type, req.threat_level,
        req.description, req.tags, req.source, cu["sub"], req.mitre_technique).to_dict()

@app.get("/api/ioc/check/{indicator}")
async def check_ioc(indicator: str, _: dict = Depends(get_current_user)):
    hit = ioc_mgr.match(indicator)
    return {"matched": hit is not None, "ioc": hit.to_dict() if hit else None}

@app.delete("/api/ioc/{ioc_id}")
async def delete_ioc(ioc_id: str, m: dict = Depends(require_master)):
    if not ioc_mgr.delete_ioc(ioc_id, m["sub"]): raise HTTPException(404,"IOC not found")
    return {"success": True}

# ── Cases ──────────────────────────────────────────────────────────────────────
@app.get("/api/cases")
async def list_cases(status: str = None, priority: str = None,
                     limit: int = 50, _: dict = Depends(get_current_user)):
    return {"cases": case_mgr.list_cases(status, priority, limit=limit), "stats": case_mgr.stats()}

@app.post("/api/cases")
async def create_case(req: CaseCreateReq, cu: dict = Depends(get_current_user)):
    case = case_mgr.create_case(req.title, req.description, req.priority,
        cu["sub"], req.attack_type, req.affected_ips, req.event_ids,
        req.alert_ids, req.mitre_technique, req.mitre_tactic, req.tags)
    threat_graph.ingest_case(case.case_id, req.affected_ips)
    return case.to_dict()

@app.get("/api/cases/{case_id}")
async def get_case(case_id: str, _: dict = Depends(get_current_user)):
    c = case_mgr.get_case(case_id)
    if not c: raise HTTPException(404,"Case not found")
    return c.to_dict()

@app.post("/api/cases/{case_id}/assign")
async def assign_case(case_id: str, req: CaseAssignReq, m: dict = Depends(require_master)):
    r = case_mgr.assign_case(case_id, req.assigned_to, m["sub"])
    if not r: raise HTTPException(404,"Case not found"); return r

@app.post("/api/cases/{case_id}/status")
async def case_status(case_id: str, req: CaseStatusReq, cu: dict = Depends(get_current_user)):
    r = case_mgr.update_status(case_id, req.status, cu["sub"], req.note)
    if not r: raise HTTPException(404,"Case not found"); return r

    # ── Adaptive Risk Weight Learning feedback hook ──────────────────────
    # A case moving to CLOSED (genuine resolved threat) or FALSE_POSITIVE
    # gives us a labeled training sample for the weight learner.
    status_upper = (req.status or "").upper()
    if status_upper in ("CLOSED", "FALSE_POSITIVE"):
        label = 0 if status_upper == "FALSE_POSITIVE" else 1
        affected_ips = r.get("affected_ips", []) if isinstance(r, dict) else []
        for ip in affected_ips:
            cached = _risk_feedback_cache.get(ip)
            if not cached:
                continue
            sample = FeedbackSample(
                src_ip=ip, label=label,
                components=cached["components"],
                predicted_risk=cached["predicted_risk"],
            )
            try:
                weight_learner.record_feedback(sample)
            except Exception as e:
                logger.warning(f"Adaptive learning feedback failed for {ip}: {e}")
    return r

@app.post("/api/cases/{case_id}/notes")
async def case_note(case_id: str, req: CaseNoteReq, cu: dict = Depends(get_current_user)):
    r = case_mgr.add_note(case_id, cu["sub"], req.content, req.note_type)
    if not r: raise HTTPException(404,"Case not found"); return r

@app.post("/api/cases/{case_id}/resolve")
async def resolve_case(case_id: str, req: CaseResolveReq, cu: dict = Depends(get_current_user)):
    r = case_mgr.resolve_case(case_id, cu["sub"], req.resolution)
    if not r: raise HTTPException(404,"Case not found"); return r

@app.post("/api/cases/{case_id}/close")
async def close_case(case_id: str, req: CaseCloseReq, m: dict = Depends(require_master)):
    r = case_mgr.close_case(case_id, m["sub"], req.notes)
    if not r: raise HTTPException(404,"Case not found"); return r

# ── Correlation ────────────────────────────────────────────────────────────────
@app.get("/api/correlation/incidents")
async def get_incidents(limit: int = 50, _: dict = Depends(get_current_user)):
    return {"incidents": corr_engine.recent_incidents(limit), "stats": corr_engine.stats()}

@app.post("/api/correlation/incidents/{incident_id}/acknowledge")
async def ack_incident(incident_id: str, m: dict = Depends(require_master)):
    if not corr_engine.acknowledge(incident_id): raise HTTPException(404,"Not found")
    return {"success": True}

# ── Threat Hunting ─────────────────────────────────────────────────────────────
@app.post("/api/hunt")
async def threat_hunt(req: ThreatHuntReq, _: dict = Depends(get_current_user)):
    events = evt_mgr.recent_events(500)
    qt = req.query_type.lower(); q = req.query.lower()
    if   qt == "ip":          results = [e for e in events if q in e.get("src_ip","").lower() or q in e.get("dst_ip","").lower()]
    elif qt == "attack_type": results = [e for e in events if q in e.get("attack_type","").lower()]
    elif qt == "country":     results = [e for e in events if q in e.get("country","").lower()]
    elif qt == "protocol":    results = [e for e in events if q in e.get("protocol","").lower()]
    elif qt == "severity":    results = [e for e in events if q in e.get("severity","").lower()]
    elif qt == "mitre":       results = [e for e in events if q in e.get("mitre_technique","").lower()]
    elif qt == "port":
        try: port=int(req.query); results=[e for e in events if e.get("dst_port")==port or e.get("src_port")==port]
        except: results=[]
    else: results=[e for e in events if q in json.dumps(e).lower()]
    for e in results[:100]:
        mr = mitre_map.map(e.get("attack_type","Normal"))
        if mr: e["mitre_technique"]=mr.technique_id; e["mitre_tactic"]=mr.tactic
    return {"query":req.query,"query_type":req.query_type,
            "total_searched":len(events),"results":results[:100],"result_count":len(results)}

# ── Honeypot ───────────────────────────────────────────────────────────────────
@app.get("/api/honeypot/hits")
async def honeypot_hits(limit: int = 50, _: dict = Depends(get_current_user)):
    return {"hits": honeypot.recent_hits(limit), "stats": honeypot.stats()}

@app.post("/api/honeypot/toggle")
async def honeypot_toggle(req: ToggleReq, m: dict = Depends(require_master)):
    result = honeypot.start() if req.enabled else {}
    if not req.enabled: honeypot.stop()
    return {"enabled": req.enabled, "services": result}

# ── Asset Management ───────────────────────────────────────────────────────────
@app.get("/api/assets")
async def list_assets(_: dict = Depends(get_current_user)):
    return {"assets": asset_mgr.list_assets(), "stats": asset_mgr.stats()}

@app.post("/api/assets")
async def add_asset(req: AssetCreateReq, m: dict = Depends(require_master)):
    a = asset_mgr.add_asset(req.name, req.ip, req.asset_type, req.criticality,
        req.owner, req.description, req.tags, req.os, req.location)
    return a.to_dict()

@app.delete("/api/assets/{asset_id}")
async def delete_asset(asset_id: str, m: dict = Depends(require_master)):
    if not asset_mgr.delete_asset(asset_id): raise HTTPException(404,"Asset not found")
    return {"success": True}

@app.get("/api/assets/lookup/{ip}")
async def lookup_asset(ip: str, _: dict = Depends(get_current_user)):
    a = asset_mgr.get_by_ip(ip)
    return a.to_dict() if a else {"found": False}

# ── UBA ────────────────────────────────────────────────────────────────────────
@app.get("/api/uba/alerts")
async def uba_alerts(limit: int = 50, _: dict = Depends(get_current_user)):
    return {"alerts": uba_engine.get_alerts(limit), "stats": uba_engine.stats()}

@app.get("/api/uba/profiles")
async def uba_profiles(m: dict = Depends(require_master)):
    return {"profiles": uba_engine.all_profiles()}

@app.get("/api/uba/profile/{username}")
async def uba_profile(username: str, m: dict = Depends(require_master)):
    p = uba_engine.get_profile(username)
    if not p: raise HTTPException(404,"User profile not found")
    return p

# ── SOAR ───────────────────────────────────────────────────────────────────────
@app.get("/api/soar/runs")
async def soar_runs(limit: int = 50, _: dict = Depends(get_current_user)):
    return {"runs": soar_engine.recent_runs(limit), "stats": soar_engine.stats()}

# ── Firewall ───────────────────────────────────────────────────────────────────
@app.get("/api/firewall/status")
async def fw_status(m: dict = Depends(require_master)): return firewall.status()

@app.post("/api/firewall/toggle")
async def fw_toggle(req: ToggleReq, m: dict = Depends(require_master)):
    if not firewall.set_toggle(req.feature, req.enabled, m["sub"]): raise HTTPException(400,"Unknown toggle")
    return {"success":True,"toggles":firewall.toggles.to_dict()}

@app.get("/api/firewall/blocked-ips")
async def blocked_ips(m: dict = Depends(require_master)):
    return {"blocked":firewall.blocked_ips_list(),"whitelist":firewall.whitelist_list()}

@app.post("/api/firewall/block-ip")
async def block_ip(req: BlockIPReq, m: dict = Depends(require_master)):
    return firewall.block_ip(req.ip, req.reason, m["sub"])

@app.post("/api/firewall/unblock-ip")
async def unblock_ip(req: BlockIPReq, m: dict = Depends(require_master)):
    return firewall.unblock_ip(req.ip, m["sub"])

@app.get("/api/firewall/blocked-ports")
async def blocked_ports(m: dict = Depends(require_master)): return {"ports":firewall.blocked_ports_list()}

@app.post("/api/firewall/block-port")
async def block_port(req: BlockPortReq, m: dict = Depends(require_master)):
    return firewall.block_port(req.port, req.protocol, req.reason, m["sub"])

@app.post("/api/firewall/unblock-port/{port}")
async def unblock_port(port: int, m: dict = Depends(require_master)):
    return firewall.unblock_port(port, m["sub"])

@app.get("/api/firewall/whitelist")
async def get_wl(m: dict = Depends(require_master)): return {"whitelist":firewall.whitelist_list()}

@app.post("/api/firewall/whitelist/add")
async def wl_add(req: WLReq, m: dict = Depends(require_master)):
    firewall.add_to_whitelist(req.ip, m["sub"]); return {"success":True}

@app.post("/api/firewall/whitelist/remove")
async def wl_rm(req: WLReq, m: dict = Depends(require_master)):
    firewall.remove_from_whitelist(req.ip, m["sub"]); return {"success":True}

@app.get("/api/firewall/audit")
async def fw_audit(limit: int = 100, m: dict = Depends(require_master)):
    return {"audit":firewall.audit_log(limit)}

@app.get("/api/firewall/rules")
async def fw_rules(m: dict = Depends(require_master)): return {"rules":firewall.all_rules()}

# ── Adaptive Risk Weight Learning ────────────────────────────────────────────
@app.get("/api/adaptive-learning/stats")
async def adaptive_stats(_: dict = Depends(get_current_user)):
    return weight_learner.stats()

@app.get("/api/adaptive-learning/weights")
async def adaptive_weights(_: dict = Depends(get_current_user)):
    return {"weights": weight_learner.get_weights()}

@app.get("/api/adaptive-learning/history")
async def adaptive_history(limit: int = 100, _: dict = Depends(get_current_user)):
    return {"history": weight_learner.weight_history(limit)}

@app.get("/api/adaptive-learning/convergence")
async def adaptive_convergence(_: dict = Depends(get_current_user)):
    """Weight values at each update step — for the IEEE paper's convergence plot."""
    return {"convergence": weight_learner.convergence_curve()}

@app.post("/api/adaptive-learning/reset")
async def adaptive_reset(m: dict = Depends(require_master)):
    weight_learner.reset_to_defaults()
    return {"success": True, "weights": weight_learner.get_weights()}

@app.post("/api/adaptive-learning/feedback")
async def adaptive_manual_feedback(req: AdaptiveFeedbackReq, m: dict = Depends(require_master)):
    """Manually submit a labeled sample (for testing / synthetic data / dataset eval)."""
    sample = FeedbackSample(
        src_ip=req.src_ip, label=req.label,
        components=req.components, predicted_risk=req.predicted_risk,
    )
    new_weights = weight_learner.record_feedback(sample)
    return {"success": True, "weights": new_weights, "stats": weight_learner.stats()}

# ── Temporal Attack Prediction ───────────────────────────────────────────────
@app.get("/api/forecast/{ip}")
async def forecast_ip(ip: str, _: dict = Depends(get_current_user)):
    """Forecast the next N risk scores for a single IP based on its history."""
    history = hist_risk.get_history(ip, "ip")
    if not history or len(history.recent_events) < 1:
        raise HTTPException(404, f"No history found for {ip}")
    result = predictor.predict_from_events(ip, history.recent_events)
    return result.to_dict()

@app.get("/api/forecast/escalating/top")
async def forecast_top_escalating(n: int = 10, _: dict = Depends(get_current_user)):
    """Returns the N IPs with the strongest upward risk trend — i.e.
    indicators an analyst should investigate before they peak/breach."""
    series = hist_risk.get_all_risk_series("ip", min_events=3)
    top = predictor.top_escalating(series, n=n)
    return {"escalating": [r.to_dict() for r in top], "total_tracked": len(series)}

@app.get("/api/forecast/fleet")
async def forecast_fleet(_: dict = Depends(get_current_user)):
    """Forecast for every tracked IP — for the dashboard trend panel."""
    series = hist_risk.get_all_risk_series("ip", min_events=3)
    results = predictor.predict_fleet(series)
    return {
        "forecasts": [r.to_dict() for r in results],
        "summary": {
            "total": len(results),
            "escalating": sum(1 for r in results if r.trend_label == "ESCALATING"),
            "stable": sum(1 for r in results if r.trend_label == "STABLE"),
            "deescalating": sum(1 for r in results if r.trend_label == "DE-ESCALATING"),
            "will_breach_critical": sum(1 for r in results if r.will_breach_critical),
        }
    }

# ── Graph-based Threat Correlation ───────────────────────────────────────────
@app.get("/api/graph/stats")
async def graph_stats(_: dict = Depends(get_current_user)):
    return threat_graph.stats()

@app.get("/api/graph/path")
async def graph_path(source: str, target: str, _: dict = Depends(get_current_user)):
    """Shortest path between any two graph entities, e.g.
    source=45.33.32.156&target=asset:web-server-01"""
    result = threat_graph.shortest_path(source, target)
    if not result:
        raise HTTPException(404, f"No path found between {source} and {target}")
    return result.to_dict()

@app.get("/api/graph/blast-radius/{ip}")
async def graph_blast_radius(ip: str, hops: int = 2, _: dict = Depends(get_current_user)):
    """If this IP is compromised, what assets/IOCs/IPs are within N hops?"""
    return threat_graph.blast_radius(ip, hops=hops)

@app.get("/api/graph/centrality")
async def graph_centrality(top_n: int = 10, _: dict = Depends(get_current_user)):
    """Highest-centrality nodes — pivot points worth investigating even
    if their own risk score looks moderate."""
    return {"ranking": threat_graph.centrality_ranking(top_n=top_n)}

@app.get("/api/graph/campaigns")
async def graph_campaigns(min_size: int = 3, _: dict = Depends(get_current_user)):
    """Connected-component clustering — groups of entities that are
    linked, suggesting a coordinated campaign rather than isolated events."""
    clusters = threat_graph.find_campaigns(min_cluster_size=min_size)
    return {"campaigns": [c.to_dict() for c in clusters], "total": len(clusters)}

@app.get("/api/graph/related-ioc/{indicator}")
async def graph_related_ioc(indicator: str, hops: int = 2, _: dict = Depends(get_current_user)):
    """All IPs within N hops of a known-bad IOC indicator."""
    related = threat_graph.related_to_ioc(indicator, hops=hops)
    return {"indicator": indicator, "related_ips": related, "count": len(related)}

@app.post("/api/graph/clear")
async def graph_clear(m: dict = Depends(require_master)):
    threat_graph.clear()
    return {"success": True}

# ── Maintenance / Clear Data ───────────────────────────────────────────────────
@app.post("/api/maintenance/clear")
async def clear_data(req: ClearDataReq, m: dict = Depends(require_master)):
    """Clear in-memory AND MongoDB data stores."""
    import shutil
    cleared = []
    base = os.path.dirname(__file__)

    if req.target in ("events", "all"):
        evt_mgr.clear()
        cleared.append("events (memory)")
        try:
            from database import get_collection
            col = get_collection("security_events")
            if col is not None:
                col.delete_many({}); cleared.append("events (MongoDB)")
        except Exception as e:
            logger.warning(f"MongoDB events clear failed: {e}")

    if req.target in ("alerts", "all"):
        alert_mgr.clear_notifications()
        cleared.append("alerts (memory)")
        try:
            from database import get_collection
            col = get_collection("alerts")
            if col is not None:
                col.delete_many({}); cleared.append("alerts (MongoDB)")
        except Exception as e:
            logger.warning(f"MongoDB alerts clear failed: {e}")

    if req.target in ("correlations", "all"):
        corr_engine._incidents.clear()
        cleared.append("correlations")

    if req.target in ("cases", "all"):
        case_mgr._cases.clear()
        cleared.append("cases (memory)")
        try:
            from database import get_collection
            col = get_collection("cases")
            if col is not None:
                col.delete_many({}); cleared.append("cases (MongoDB)")
        except Exception as e:
            logger.warning(f"MongoDB cases clear failed: {e}")

    if req.target in ("iocs", "all"):
        try:
            from database import get_collection
            col = get_collection("iocs")
            if col is not None:
                col.delete_many({}); cleared.append("iocs (MongoDB)")
        except Exception as e:
            logger.warning(f"MongoDB IOCs clear failed: {e}")

    if req.target in ("history", "all"):
        try:
            from database import get_collection
            col = get_collection("historical_risk")
            if col is not None:
                col.delete_many({}); cleared.append("historical_risk (MongoDB)")
        except Exception as e:
            logger.warning(f"MongoDB history clear failed: {e}")

    if req.target in ("logs", "all"):
        log_dir = os.path.join(base, "logs")
        if os.path.exists(log_dir):
            import shutil
            shutil.rmtree(log_dir, ignore_errors=True)
            os.makedirs(log_dir, exist_ok=True)
            cleared.append("logs (files)")
        else:
            cleared.append("logs (dir not found)")

    if req.target in ("reports", "all"):
        rep_dir = os.path.join(base, "reports")
        if os.path.exists(rep_dir):
            import shutil
            shutil.rmtree(rep_dir, ignore_errors=True)
            os.makedirs(rep_dir, exist_ok=True)
            cleared.append("reports (files)")
        else:
            cleared.append("reports (dir not found)")

    if req.target in ("models", "all"):
        models_dir = os.path.join(base, "models")
        if os.path.exists(models_dir):
            for f in os.listdir(models_dir):
                fp = os.path.join(models_dir, f)
                if os.path.isfile(fp):
                    os.remove(fp)
            cleared.append("models (pkl files)")

    logger.info(f"Data cleared by {m['sub']}: {cleared}")
    return {"success": True, "cleared": cleared,
            "message": f"Cleared: {', '.join(cleared)}"}


@app.get("/api/maintenance/stats")
async def maintenance_stats(m: dict = Depends(require_master)):
    base = os.path.dirname(__file__)

    def dir_size_kb(path):
        total = 0
        if os.path.exists(path):
            for r, _, files in os.walk(path):
                for f in files:
                    try: total += os.path.getsize(os.path.join(r, f))
                    except: pass
        return total // 1024

    def dir_file_count(path):
        if not os.path.exists(path): return 0
        return sum(1 for r, _, files in os.walk(path) for f in files)

    # MongoDB collection sizes
    mongo_stats = {}
    try:
        from database import get_collection, get_db
        db = get_db()
        if db is not None:
            for col_name in ["security_events", "alerts", "cases", "iocs",
                             "historical_risk", "forensics"]:
                try:
                    mongo_stats[col_name] = db[col_name].count_documents({})
                except: mongo_stats[col_name] = -1
    except: pass

    return {
        "events_in_memory":          evt_mgr.total_count(),
        "cases_in_memory":           case_mgr.stats()["total"],
        "iocs_active":               ioc_mgr.stats()["total"],
        "correlation_incidents":     corr_engine.stats()["total_incidents"],
        "soar_runs":                 soar_engine.stats()["total_runs"],
        "log_size_kb":               dir_size_kb(os.path.join(base, "logs")),
        "log_file_count":            dir_file_count(os.path.join(base, "logs")),
        "reports_size_kb":           dir_size_kb(os.path.join(base, "reports")),
        "reports_file_count":        dir_file_count(os.path.join(base, "reports")),
        "models_size_kb":            dir_size_kb(os.path.join(base, "models")),
        "mongodb_collection_counts": mongo_stats,
    }


@app.delete("/api/maintenance/mongodb/{collection}")
async def purge_mongodb_collection(collection: str, m: dict = Depends(require_master)):
    """Purge a specific MongoDB collection by name."""
    ALLOWED = {"security_events", "alerts", "cases", "iocs",
               "historical_risk", "forensics", "correlation_incidents"}
    if collection not in ALLOWED:
        raise HTTPException(400, f"Collection '{collection}' not allowed. Choose from: {sorted(ALLOWED)}")
    try:
        from database import get_collection
        col = get_collection(collection)
        if col is None:
            raise HTTPException(503, "MongoDB not connected")
        result = col.delete_many({})
        logger.info(f"MongoDB collection '{collection}' purged by {m['sub']}: {result.deleted_count} docs")
        return {"success": True, "collection": collection, "deleted": result.deleted_count}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))

# ── Ransomware / Virus ─────────────────────────────────────────────────────────
@app.get("/api/ransomware/alerts")
async def ransom_alerts(limit: int = 50, _: dict = Depends(get_current_user)):
    return {"alerts":ransomware.recent_alerts(limit),"stats":ransomware.stats()}

@app.post("/api/ransomware/toggle")
async def ransom_toggle(req: ToggleReq, m: dict = Depends(require_master)):
    ransomware.enabled=req.enabled; return {"enabled":ransomware.enabled}

@app.get("/api/virus/alerts")
async def virus_alerts(limit: int = 50, _: dict = Depends(get_current_user)):
    return {"alerts":virus_det.recent_alerts(limit),"stats":virus_det.stats()}

@app.post("/api/virus/toggle")
async def virus_toggle(req: ToggleReq, m: dict = Depends(require_master)):
    virus_det.enabled=req.enabled; return {"enabled":virus_det.enabled}

# ── Alerts / Reports / Notifications ──────────────────────────────────────────
@app.post("/api/alerts/submit")
async def submit_alert(req: AlertSubmitReq, cu: dict = Depends(get_current_user)):
    return alert_mgr.submit_alert(req.title,req.description,req.priority,
        cu["sub"],req.target_ip,req.attack_type,req.event_ids).to_dict()

@app.get("/api/alerts")
async def list_alerts(status: str = None, limit: int = 50, _: dict = Depends(get_current_user)):
    return {"alerts":alert_mgr.list_alerts(status,limit)}

@app.post("/api/alerts/{alert_id}/update")
async def update_alert(alert_id: str, req: ReviewReq, m: dict = Depends(require_master)):
    r=alert_mgr.update_alert_status(alert_id,req.status,m["sub"],req.notes)
    if not r: raise HTTPException(404,"Alert not found"); return r

@app.post("/api/alerts/{alert_id}/acknowledge")
async def ack_alert(alert_id: str, req: ReviewReq, m: dict = Depends(require_master)):
    r=alert_mgr.acknowledge_alert(alert_id,m["sub"],req.notes,req.action)
    if not r: raise HTTPException(404,"Alert not found"); return r

@app.post("/api/reports/submit")
async def submit_report(req: ReportSubmitReq, cu: dict = Depends(get_current_user)):
    return alert_mgr.submit_report(req.title,req.summary,req.findings,
        req.recommendations,cu["sub"],req.severity,req.affected_ips,req.event_ids).to_dict()

@app.get("/api/reports")
async def list_reports(limit: int = 50, _: dict = Depends(get_current_user)):
    return {"reports":alert_mgr.list_reports(limit)}

@app.post("/api/reports/{report_id}/review")
async def review_report(report_id: str, req: ReviewReq, m: dict = Depends(require_master)):
    r=alert_mgr.review_report(report_id,m["sub"],req.status,req.notes)
    if not r: raise HTTPException(404,"Report not found"); return r

@app.get("/api/notifications")
async def get_notifs(unread_only: bool = False, _: dict = Depends(get_current_user)):
    return {"notifications":alert_mgr.get_notifications(unread_only),"unread_count":alert_mgr.unread_count()}

@app.post("/api/notifications/mark-read")
async def mark_read(_: dict = Depends(get_current_user)):
    alert_mgr.mark_notifications_read(); return {"success":True}

# ── Download Reports ───────────────────────────────────────────────────────────
@app.get("/api/download-report")
async def download_report(_: dict = Depends(get_current_user)):
    html = report_gen.executive_report(
        events=evt_mgr.recent_events(500), severity_counts=evt_mgr.severity_counts(),
        attack_counts=evt_mgr.attack_type_counts(), incidents=corr_engine.recent_incidents(20),
        cases_stats=case_mgr.stats(), ioc_stats=ioc_mgr.stats(),
    )
    return HTMLResponse(content=html,
        headers={"Content-Disposition":f"attachment; filename=AHRAS_Report_{int(time.time())}.html"})

@app.get("/api/download-report/incident/{incident_id}")
async def download_incident_report(incident_id: str, _: dict = Depends(get_current_user)):
    incidents = corr_engine.recent_incidents(200)
    inc = next((i for i in incidents if i["incident_id"]==incident_id),None)
    if not inc: raise HTTPException(404,"Incident not found")
    evts = [e for e in evt_mgr.recent_events(200) if e.get("src_ip")==inc.get("src_ip")][:20]
    html = report_gen.incident_report(inc,evts)
    return HTMLResponse(content=html,
        headers={"Content-Disposition":f"attachment; filename=AHRAS_Incident_{incident_id}.html"})

# ══════════════════════════════════════════════════════════════════════════════
# THREAT HUNTING ROUTES
# ══════════════════════════════════════════════════════════════════════════════

class HuntReq(BaseModel):
    query: str
    query_type: str = "auto"  # ip | domain | url | hash | mitre | auto

@app.post("/api/hunt")
async def hunt(req: HuntReq, _: dict = Depends(get_current_user)):
    result = threat_hunter.hunt(req.query, req.query_type)
    return result.to_dict()

@app.get("/api/hunt/ip/{ip}")
async def hunt_ip(ip: str, _: dict = Depends(get_current_user)):
    return threat_hunter.hunt_ip(ip).to_dict()

@app.get("/api/hunt/domain/{domain}")
async def hunt_domain(domain: str, _: dict = Depends(get_current_user)):
    return threat_hunter.hunt_domain(domain).to_dict()

@app.get("/api/hunt/url")
async def hunt_url(url: str, _: dict = Depends(get_current_user)):
    return threat_hunter.hunt_url(url).to_dict()

@app.get("/api/hunt/hash/{file_hash}")
async def hunt_hash(file_hash: str, _: dict = Depends(get_current_user)):
    return threat_hunter.hunt_hash(file_hash).to_dict()

@app.get("/api/hunt/mitre/{technique_id}")
async def hunt_mitre(technique_id: str, _: dict = Depends(get_current_user)):
    return threat_hunter.hunt_mitre(technique_id).to_dict()

# ══════════════════════════════════════════════════════════════════════════════
# FORENSICS ROUTES
# ══════════════════════════════════════════════════════════════════════════════

class ForensicCaseReq(BaseModel):
    case_id: str
    title: str

class EvidenceReq(BaseModel):
    ev_type: str = "other"
    title: str
    description: str
    data: str
    source: str = "analyst"
    tags: list = []
    hash_md5: str = ""
    hash_sha256: str = ""

class TimelineReq(BaseModel):
    timestamp: str
    actor: str
    action: str
    target: str
    description: str
    mitre_technique: str = ""
    severity: str = "INFO"
    evidence_ids: list = []

class NoteReq(BaseModel):
    title: str
    body: str
    tags: list = []

class NoteUpdateReq(BaseModel):
    body: str

@app.post("/api/forensics/cases")
async def create_forensic_case(req: ForensicCaseReq, cu: dict = Depends(get_current_user)):
    fc = forensics_mgr.create_case(req.case_id, req.title, analyst=cu.get("username", "analyst"))
    return fc.to_dict()

@app.get("/api/forensics/cases")
async def list_forensic_cases(status: str = None, _: dict = Depends(get_current_user)):
    return {"cases": forensics_mgr.list_cases(status=status)}

@app.get("/api/forensics/cases/{case_id}")
async def get_forensic_case(case_id: str, _: dict = Depends(get_current_user)):
    fc = forensics_mgr.get_case(case_id)
    if not fc:
        raise HTTPException(404, "Forensic case not found")
    return fc.to_dict()

@app.get("/api/forensics/cases/{case_id}/summary")
async def forensic_case_summary(case_id: str, _: dict = Depends(get_current_user)):
    return forensics_mgr.get_summary(case_id)

@app.post("/api/forensics/cases/{case_id}/evidence")
async def add_evidence(case_id: str, req: EvidenceReq, cu: dict = Depends(get_current_user)):
    ev = forensics_mgr.add_evidence(
        case_id, req.ev_type, req.title, req.description,
        req.data, req.source, collected_by=cu.get("username", "analyst"),
        tags=req.tags, hash_md5=req.hash_md5, hash_sha256=req.hash_sha256,
    )
    return ev.to_dict() if ev else {"error": "Failed to add evidence"}

@app.get("/api/forensics/cases/{case_id}/evidence")
async def list_evidence(case_id: str, _: dict = Depends(get_current_user)):
    return {"evidence": forensics_mgr.list_evidence(case_id)}

@app.delete("/api/forensics/cases/{case_id}/evidence/{evidence_id}")
async def delete_evidence(case_id: str, evidence_id: str, _: dict = Depends(require_master)):
    ok = forensics_mgr.delete_evidence(case_id, evidence_id)
    return {"deleted": ok}

@app.post("/api/forensics/cases/{case_id}/timeline")
async def add_timeline_event(case_id: str, req: TimelineReq, cu: dict = Depends(get_current_user)):
    te = forensics_mgr.add_timeline_event(
        case_id, req.timestamp, req.actor, req.action, req.target,
        req.description, mitre_technique=req.mitre_technique,
        severity=req.severity, evidence_ids=req.evidence_ids,
        added_by=cu.get("username", "analyst"),
    )
    return te.to_dict() if te else {"error": "Failed to add event"}

@app.get("/api/forensics/cases/{case_id}/timeline")
async def get_timeline(case_id: str, _: dict = Depends(get_current_user)):
    return {"timeline": forensics_mgr.get_timeline(case_id)}

@app.post("/api/forensics/cases/{case_id}/notes")
async def add_note(case_id: str, req: NoteReq, cu: dict = Depends(get_current_user)):
    note = forensics_mgr.add_note(case_id, req.title, req.body,
                                   author=cu.get("username", "analyst"), tags=req.tags)
    return note.to_dict() if note else {"error": "Failed"}

@app.get("/api/forensics/cases/{case_id}/notes")
async def list_notes(case_id: str, _: dict = Depends(get_current_user)):
    return {"notes": forensics_mgr.list_notes(case_id)}

@app.put("/api/forensics/cases/{case_id}/notes/{note_id}")
async def update_note(case_id: str, note_id: str, req: NoteUpdateReq, _: dict = Depends(get_current_user)):
    ok = forensics_mgr.update_note(case_id, note_id, req.body)
    return {"updated": ok}

# ══════════════════════════════════════════════════════════════════════════════
# LOG NORMALIZER ROUTES
# ══════════════════════════════════════════════════════════════════════════════

class NormalizeReq(BaseModel):
    logs: list   # list of raw log dicts

@app.post("/api/normalizer/normalize")
async def normalize_logs(req: NormalizeReq, _: dict = Depends(get_current_user)):
    normalised = log_normalizer.normalise_batch(req.logs)
    return {"count": len(normalised), "events": normalised}

@app.post("/api/normalizer/normalize-one")
async def normalize_one(req: dict, _: dict = Depends(get_current_user)):
    return log_normalizer.normalise(req)

@app.get("/api/normalizer/schema")
async def normalizer_schema(_: dict = Depends(get_current_user)):
    return log_normalizer.describe_schema()

@app.get("/api/normalizer/stats")
async def normalizer_stats(_: dict = Depends(get_current_user)):
    return log_normalizer.stats()

# ══════════════════════════════════════════════════════════════════════════════
# RISK EXPLAINER ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/risk/explain/{src_ip}")
async def explain_risk(src_ip: str, _: dict = Depends(get_current_user)):
    """
    Generate a full risk explanation for a given source IP.
    Scores a synthetic event for that IP through the risk engine,
    then breaks the result into labelled sub-components.
    """
    det = {"src_ip": src_ip, "attack_type": "Normal",
           "confidence": 0.5, "packet_count": 0, "anomaly_flag": False}
    r = risk_eng.evaluate(det)
    explanation = risk_explainer.explain(r)
    exp_dict = explanation.to_dict()
    _explanation_history.append(exp_dict)
    if len(_explanation_history) > _EXPLANATION_HISTORY_MAXLEN:
        _explanation_history.pop(0)
    return exp_dict

@app.post("/api/risk/explain")
async def explain_risk_from_event(req: dict, _: dict = Depends(get_current_user)):
    """
    Accept a raw detection dict, run it through the risk engine,
    and return the scored + explained result.
    """
    r = risk_eng.evaluate(req)
    uba_score = float(req.get("uba_score", 0.0))
    ti_score  = float(req.get("threat_intel_score", 0.0))
    ac_score  = float(req.get("asset_criticality", 0.0))
    explanation = risk_explainer.explain(r, uba_score=uba_score,
                                         threat_intel_score=ti_score,
                                         asset_criticality=ac_score)
    exp_dict = explanation.to_dict()
    _explanation_history.append(exp_dict)
    if len(_explanation_history) > _EXPLANATION_HISTORY_MAXLEN:
        _explanation_history.pop(0)
    return {**r.to_dict(), "explanation": exp_dict}

@app.get("/api/risk/weights")
async def risk_weights(_: dict = Depends(get_current_user)):
    """Return the component weight configuration used by the explainer."""
    from risk_explainer.explainer import WEIGHTS
    return {"weights": WEIGHTS, "description": "Points each component contributes to the 0-100 risk score"}

# ── Extended Explainable AI (counterfactuals, confidence, importance) ───────
@app.get("/api/xai/explain/{src_ip}")
async def xai_explain(src_ip: str, _: dict = Depends(get_current_user)):
    """Full XAI report: base explanation + counterfactual + confidence."""
    det = {"src_ip": src_ip, "attack_type": "Normal",
           "confidence": 0.5, "packet_count": 0, "anomaly_flag": False}
    r = risk_eng.evaluate(det)
    explanation = risk_explainer.explain(r)
    exp_dict = explanation.to_dict()
    _explanation_history.append(exp_dict)
    if len(_explanation_history) > _EXPLANATION_HISTORY_MAXLEN:
        _explanation_history.pop(0)
    history = hist_risk.get_history(src_ip, "ip")
    history_depth = len(history.recent_events) if history else 0
    return xai_explainer.full_report(exp_dict, signal_strength=r.signal_strength,
                                     history_depth=history_depth)

@app.get("/api/xai/counterfactual/{src_ip}")
async def xai_counterfactual(src_ip: str, all_tiers: bool = False, _: dict = Depends(get_current_user)):
    """What's the smallest change that would lower this IP's severity tier?"""
    det = {"src_ip": src_ip, "attack_type": "Normal",
           "confidence": 0.5, "packet_count": 0, "anomaly_flag": False}
    r = risk_eng.evaluate(det)
    exp_dict = risk_explainer.explain(r).to_dict()
    if all_tiers:
        cfs = xai_explainer.all_counterfactuals(exp_dict)
        return {"src_ip": src_ip, "counterfactuals": [c.to_dict() for c in cfs]}
    cf = xai_explainer.counterfactual(exp_dict)
    return {"src_ip": src_ip, "counterfactual": cf.to_dict() if cf else None}

@app.get("/api/xai/feature-importance")
async def xai_feature_importance(_: dict = Depends(get_current_user)):
    """Global feature importance across recent explanations -- which
    risk components most often drive the verdict, for the IEEE paper."""
    importance = xai_explainer.feature_importance(_explanation_history)
    return {"importance": [f.to_dict() for f in importance],
            "sample_size": len(_explanation_history)}

# ══════════════════════════════════════════════════════════════════════════════
# RBAC ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/rbac/roles")
async def rbac_roles(_: dict = Depends(get_current_user)):
    """Return all roles and their permission sets."""
    return {"roles": role_summary()}

@app.get("/api/rbac/my-permissions")
async def my_permissions(cu: dict = Depends(get_current_user)):
    """Return the current user's role and full permission list."""
    from rbac.permissions import get_permissions
    perms = get_permissions(cu.get("role", ""))
    return {
        "username": cu.get("sub"),
        "role": cu.get("role"),
        "permissions": sorted(p.value for p in perms),
        "permission_count": len(perms),
    }

@app.get("/api/rbac/check")
async def rbac_check(permission: str, cu: dict = Depends(get_current_user)):
    """Check if the current user has a specific permission."""
    from rbac.permissions import Perm, has_permission
    try:
        perm = Perm(permission)
        allowed = has_permission(cu.get("role", ""), perm)
        return {"permission": permission, "allowed": allowed, "role": cu.get("role")}
    except ValueError:
        raise HTTPException(400, f"Unknown permission: {permission}")

# ══════════════════════════════════════════════════════════════════════════════
# HISTORICAL RISK ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/history/ip/{ip}")
async def history_ip(ip: str, _: dict = Depends(get_current_user)):
    """Full historical risk profile for a source IP."""
    h = hist_risk.get_history_dict(ip, "ip")
    if not h:
        return {"indicator": ip, "message": "No history found", "history_boost": 0}
    return h

@app.get("/api/history/domain/{domain}")
async def history_domain(domain: str, _: dict = Depends(get_current_user)):
    """Historical risk profile for a domain."""
    h = hist_risk.get_history_dict(domain, "domain")
    if not h:
        return {"indicator": domain, "message": "No history found", "history_boost": 0}
    return h

@app.get("/api/history/search")
async def history_search(q: str, _: dict = Depends(get_current_user)):
    """Search history by partial indicator match."""
    return {"results": hist_risk.search(q)}

@app.get("/api/history/top-offenders")
async def top_offenders(n: int = 20, indicator_type: str = None, _: dict = Depends(get_current_user)):
    """Return top-N repeat offenders ranked by history boost."""
    return {"offenders": hist_risk.top_repeat_offenders(n, indicator_type)}

@app.get("/api/history/summary")
async def history_summary(_: dict = Depends(get_current_user)):
    """Dashboard-ready summary of all historical risk data."""
    return hist_risk.summary()

# ── Health & Dashboard ─────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status": "ok", "version": "7.0.0",
        "total_events": evt_mgr.total_count(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mongodb": db_health(),
        "modules": {
            "mitre": True, "threat_intel": True, "ioc": True,
            "cases": True, "correlation": True,
            "honeypot": honeypot.stats()["running"],
            "assets": True, "uba": True, "soar": True, "maintenance": True,
            "rbac": True, "historical_risk": True, "forensics": True,
            "threat_hunting": True, "normalizer": True,
        }
    }

@app.get("/api/mongodb/health")
async def mongodb_health(_: dict = Depends(get_current_user)):
    """Detailed MongoDB health — connection status, size, collection counts."""
    return db_health()

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    p = os.path.join(os.path.dirname(__file__), "dashboard", "index.html")
    with open(p, encoding="utf-8") as f: return f.read()

if __name__ == "__main__":
    uvicorn.run("main:app", host=config.API_HOST, port=config.API_PORT, reload=False, log_level="info")