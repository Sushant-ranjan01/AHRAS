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
from soar import SOAREngine
from threat_hunting import ThreatHunter
from forensics import ForensicsManager
from normalizer import LogNormalizer
from risk_explainer import RiskExplainer
from collectors import WindowsLogCollector, LinuxLogCollector, ApacheLogCollector
from rbac import Perm, Role, require_permission, require_role, require_admin, role_summary
from historical_risk import HistoricalRiskEngine
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
risk_explainer  = RiskExplainer()
hist_risk       = HistoricalRiskEngine()

_pkt_q  = queue.Queue(maxsize=5000)
_flow_q = queue.Queue(maxsize=2000)
sniffer  = PacketSniffer(_pkt_q)
flow_gen = FlowGenerator(_pkt_q, _flow_q)
detector = HybridDetectionEngine()
risk_eng = RiskEngine()
risk_eng.set_asset_manager(asset_mgr)   # inject asset manager
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
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Mount external API v1
app.include_router(api_router, prefix="/api/v1")

# Wire ThreatHunter to all data sources
threat_hunter.inject(
    alert_mgr=alert_mgr, case_mgr=case_mgr,
    threat_intel=threat_intel, ioc_mgr=ioc_mgr,
    mitre=mitre_map, risk_engine=risk_eng,
)

# Wire up SOAR
soar_engine.inject(firewall=firewall, case_mgr=case_mgr, ioc_mgr=ioc_mgr,
                   alert_mgr=alert_mgr, report_gen=report_gen)

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
            risk = risk_eng.evaluate(det)
            ev   = evt_mgr.store(det, risk)
            info = enricher.enrich(ev.src_ip)
            ev.country = info["country"]; ev.organization = info["organization"]
            ev.dns_name = info["dns_name"]; ev.is_private  = info["is_private"]

            # Record in history engine
            hist_risk.record_event({
                "src_ip": ev.src_ip,
                "attack_type": getattr(det, "attack_type", "Normal"),
                "severity": risk.severity,
            }, risk.risk_score_100)

            if risk.overall >= firewall.AUTO_BLOCK_RISK and firewall.toggles.auto_block:
                firewall.block_ip(ev.src_ip, f"auto-block risk={risk.overall:.2f}")

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
                if ti_result.is_malicious:
                    ev_dict["ti_malicious"]   = True
                    ev_dict["ti_confidence"]  = ti_result.confidence

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
    ip = request.client.host if request.client else "unknown"
    token = auth_mgr.authenticate(form.username, form.password, ip)
    if not token: raise HTTPException(401, "Invalid credentials")
    user = auth_mgr.get_user(form.username)
    # UBA: record login
    uba_engine.record_login(form.username, ip)
    return {"access_token": token, "token_type": "bearer",
            "role": user.role.value, "username": form.username}

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
    return case_mgr.create_case(req.title, req.description, req.priority,
        cu["sub"], req.attack_type, req.affected_ips, req.event_ids,
        req.alert_ids, req.mitre_technique, req.mitre_tactic, req.tags).to_dict()

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
    return explanation.to_dict()

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
    return {**r.to_dict(), "explanation": explanation.to_dict()}

@app.get("/api/risk/weights")
async def risk_weights(_: dict = Depends(get_current_user)):
    """Return the component weight configuration used by the explainer."""
    from risk_explainer.explainer import WEIGHTS
    return {"weights": WEIGHTS, "description": "Points each component contributes to the 0-100 risk score"}

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
