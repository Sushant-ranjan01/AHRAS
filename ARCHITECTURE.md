# AHRAS — Architecture Reference
## Version 6.0

---

## System Overview

AHRAS is a single-server Python application built on FastAPI. Every component is a Python package that can be imported and tested independently. The main.py file wires them together via dependency injection at startup.

```
                        ┌─────────────────────────────────┐
                        │         Browser Dashboard        │
                        │      dashboard/index.html        │
                        └─────────────┬───────────────────┘
                                      │ HTTP / WebSocket
                        ┌─────────────▼───────────────────┐
                        │         FastAPI (main.py)        │
                        │    /api/* routes + /api/v1/*     │
                        └─┬──────────┬──────────┬─────────┘
                          │          │          │
              ┌───────────▼┐  ┌──────▼──┐  ┌───▼──────────┐
              │  Detection  │  │  Risk   │  │    RBAC      │
              │  Pipeline   │  │ Engine  │  │  rbac/       │
              └───────────┬┘  └──────┬──┘  └──────────────┘
                          │          │
              ┌───────────▼──────────▼────────────────────┐
              │              Data Modules                   │
              │  alerts/ cases/ forensics/ threat_intel/   │
              │  ioc_management/ correlation/ uba/ soar/   │
              │  historical_risk/ threat_hunting/           │
              └───────────────────────────────────────────┘
```

---

## Module Map

### Core Detection Pipeline

| Module | Path | Input | Output |
|---|---|---|---|
| PacketSniffer | `sensors/packet_sniffer.py` | Network interface | Raw packets → queue |
| FlowGenerator | `sensors/flow_generator.py` | Synthetic params | Simulated flows → queue |
| FeatureExtractor | `feature_engineering/` | Raw flow | Feature vector (dict) |
| SignatureEngine | `detection/signature_engine/` | Feature vector | attack_type, confidence |
| AnomalyDetector | `detection/anomaly_engine/` | Feature vector | anomaly_score (0–1) |
| HybridDetectionEngine | `detection/hybrid_detection.py` | Feature vector | Combined detection result |
| RiskEngine | `risk_engine/risk_scorer.py` | Detection result | RiskResult (0–100) |

### v5/v6 Modules

| Module | Path | Purpose |
|---|---|---|
| RiskExplainer | `risk_explainer/` | Decompose score into 5 named components |
| ThreatHunter | `threat_hunting/` | Cross-source pivot search on any indicator |
| ForensicsManager | `forensics/` | Evidence / Timeline / Notes per case |
| LogNormalizer | `normalizer/` | Any log format → unified schema |
| WindowsLogCollector | `collectors/windows_collector.py` | Read Windows Event Log |
| LinuxLogCollector | `collectors/linux_collector.py` | Read Linux auth/syslog/audit |
| ApacheLogCollector | `collectors/apache_collector.py` | Parse Apache/Nginx access logs |
| HistoricalRiskEngine | `historical_risk/` | Track repeat offenders, add recidivism boost |
| RBAC | `rbac/` | Role-based permission enforcement |
| External API | `api/router.py` | Clean `/api/v1/` integration layer |

---

## Data Flow — Single Event End-to-End

```
1. Ingestion
   PacketSniffer OR FlowGenerator
   └── raw flow dict → _pkt_q

2. Feature Extraction
   FlowGenerator reads _pkt_q → extracts features → _flow_q

3. Analysis Worker (_analysis_worker thread)
   a. HybridDetectionEngine.analyse(flow)
      ├── SignatureEngine.detect()  → attack_type, confidence
      └── AnomalyDetector.predict() → anomaly_flag
   b. HistoricalRiskEngine.get_boost(src_ip) → history_boost
   c. RiskEngine.evaluate(det) → RiskResult (0–100, severity)
   d. EventManager.store(det, risk) → Event record
   e. EnrichmentService.enrich(ip) → country, org, dns
   f. HistoricalRiskEngine.record_event()

4. Threat Context (attack events only)
   ├── MitreMapper.map(attack_type) → technique_id, tactic
   ├── IOCManager.match_ip(ip)      → IOC hit or None
   └── ThreatIntelManager.check_ip(ip) → TI result (AbuseIPDB/VT/OTX)

5. Correlation
   CorrelationEngine.ingest(event_dict)
   └── Incident created if kill-chain pattern matched

6. Response
   ├── SOAR.on_high_risk()          → playbook execution
   ├── SOAR.on_ioc_match()          → playbook execution
   ├── HistoricalRiskEngine.record_alert/incident()
   └── FirewallManager.block_ip()   → only if auto_block=True (default: OFF)
```

---

## RBAC Architecture

### Roles and Permission Counts

| Role | Permissions | Description |
|---|---|---|
| Admin | All (40+) | Full system control |
| SOC Analyst | 20 | Alert triage, event review, case management |
| Threat Hunter | 16 | Hunting, IOC, TI, risk explanation |
| Incident Responder | 21 | SOAR, forensics, case management |
| Manager | 13 | Read-only dashboard and reports |

### How RBAC Works in Routes

```python
# In main.py or any route file:
from rbac import require_permission
from rbac.permissions import Perm

@app.get("/api/hunt/ip/{ip}")
async def hunt_ip(ip: str, _=Depends(require_permission(Perm.HUNT_EXECUTE))):
    ...

# Admin-only route:
@app.post("/api/firewall/toggle")
async def toggle_fw(req, _=Depends(require_admin)):
    ...
```

The `require_permission(perm)` factory returns a FastAPI dependency that:
1. Reads the JWT token from the Authorization header
2. Extracts the user's role
3. Looks up permissions for that role in `ROLE_PERMISSIONS`
4. Returns 403 with a descriptive message if the permission is missing

---

## Historical Risk Engine

### How It Works

Every event processed by AHRAS is recorded in the HistoricalRiskEngine keyed by indicator (IP, domain, username, hash). When a new event arrives for a known indicator, the engine applies a boost:

```
incident_boost  = min(30, incident_count × 2)
alert_boost     = min(15, alert_count)
recency_factor  = 1.0 (< 7 days) | 0.5 (7–30 days) | 0.25 (> 30 days)
history_boost   = (incident_boost + alert_boost) × recency_factor
```

**Example:** An IP involved in 15 incidents + 10 alerts, last seen 3 days ago:
```
incident_boost = min(30, 15 × 2) = 30
alert_boost    = min(15, 10)     = 10
recency_factor = 1.0             (< 7 days)
history_boost  = (30 + 10) × 1.0 = 40 pts
```

This boost is injected into the RiskEngine before scoring, so repeat offenders automatically score higher.

---

## Threat Intelligence Flow

```
Any indicator (IP/domain/hash/URL)
         │
         ▼
ThreatIntelManager.check_*(indicator)
         │
         ├── Cache hit? → return cached result (TTL: 1 hour)
         │
         ├── AbuseIPDB API (IP only, if key configured)
         │         → confidence score 0–100, ISP, country, reports
         │
         ├── AlienVault OTX API (IP + domain, if key configured)
         │         → pulse count, threat tags, ASN
         │
         ├── VirusTotal API (hash + domain + URL, if key configured)
         │         → malicious/total ratio, threat labels
         │
         └── AHRAS built-in database (fallback, no key needed)
                   → known-bad IPs/domains/hashes hardcoded
                   → deterministic simulation for unknown IPs
```

---

## External API v1 Design

The `/api/v1/` layer is a clean integration surface designed for:
- SIEM connectors sending log data to AHRAS
- Scripts that need to check IPs or submit IOCs programmatically
- Third-party dashboards querying risk scores
- CI/CD pipelines checking deployment IPs

All v1 endpoints use the same JWT auth as the dashboard.  
The router is mounted at startup: `app.include_router(api_router, prefix="/api/v1")`  
Swagger documentation: `http://localhost:8000/docs`

---

## Technology Choices

| Decision | Choice | Reason |
|---|---|---|
| Web framework | FastAPI | Async-native, auto-generates Swagger, excellent typing |
| Auth | JWT + bcrypt | Stateless, industry standard, no session DB needed |
| ML model | Isolation Forest (scikit-learn) | Best unsupervised anomaly detection for tabular data |
| Storage | In-memory Python dicts | Zero deployment friction; swap to SQLAlchemy for production |
| Frontend | Single HTML file | No build tools, no npm, works in any browser |
| Packet capture | scapy | Full-featured, pure Python, cross-platform |
| HTTP requests | requests | Simple, reliable, works with all TI APIs |

---

## v5 Architecture Review — What Feeds the Risk Score (item 6)

**Decision: only four sources are formal inputs to `RiskEngine.evaluate()`.**

| # | Source | Why it's a formal INPUT |
|---|---|---|
| 1 | Four weighted base signals (signature / anomaly / density / drift+rate) | The core per-flow evidence RiskEngine was built to fuse |
| 2 | Rule / MITRE / asset-criticality boosts | Deterministic, computed purely from *this* event |
| 3 | Trust (reverse-DNS reputation) discount | Deterministic, computed purely from *this* event's `src_ip` |
| 4 | Historical recidivism boost (`historical_risk.HistoricalRiskEngine.get_boost`) | Keyed on the same `src_ip`, computed from that IP's **past** events only, recorded to history strictly *after* scoring (see `main.py`'s analysis worker) — non-circular |

**UBA, the correlation/threat-graph engine, and the attack forecaster are deliberately kept OUT of the per-event score formula** and treated as auxiliary/contextual modules instead:

- **UBA** operates on a different entity/event stream (authenticated username logins) than RiskEngine (network-flow `src_ip`/`dst_ip` detections). There is no reliable 1:1 join key between "this flow" and "this login" in the current data model, so wiring it into the score would be a guess, not a signal.
- **The threat graph and the attack forecaster are BUILT FROM already-scored events** (`graph.ingest_event` / the forecaster trains on `historical_risk`'s risk series). Feeding their output back into the score that produced them creates a circular dependency and risks a feedback loop (rising forecast → higher score → higher forecast → …). Historical risk avoids this specifically because it's a simple counter of past *occurrences*, not a model trained on past *scores*.

**How this is surfaced to analysts:** `risk_explainer.RiskExplainer.explain()` reconstructs the score *faithfully* from `RiskResult.raw_components` (the exact numbers `RiskEngine` recorded at each step) as `components` + `adjustments`. UBA/threat-intel/externally-supplied asset-criticality are surfaced separately as `contextual_signals` — informative, but never summed into the score, so what an analyst sees can never silently disagree with what the engine actually computed. See `risk_explainer/explainer.py`'s module docstring for the "faithful-by-construction" design and why the old independent weight table (v4) was replaced.
