# AHRAS — Adaptive Hybrid Risk Assessment System
### Version 6.0 · Python 3.11 · FastAPI · Machine Learning · SIEM/SOAR

AHRAS is a full-stack, open-source **SIEM/SOAR** platform built for researchers, students, and SOC analysts. It detects threats via a dual signature+ML pipeline, explains every risk score in human-readable terms, tracks repeat offenders through historical memory, and runs entirely on a single laptop.

---

## Quick Start

```bash
unzip AHRAS_v6_Complete.zip && cd AHRAS_v6/
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # Add API keys (optional)
python main.py                # Start server
# Open http://localhost:8000  |  master / master123
```

---

## Local AI Security Intelligence Layer

AHRAS separates detection, risk calculation, and cognition into distinct layers. The local model is not the risk engine: deterministic engines and ML models compute the score, while the LLM explains what the evidence means and helps an analyst investigate the event.

```text
AHRAS Core
  ├─ Detection Engine
  ├─ ML Anomaly Detection
  ├─ Threat Intelligence
  ├─ Risk Engine
  ├─ Historical Risk
  ├─ Temporal Graph
  └─ Asset Context
           │
           ▼
   Security Context Builder
           │
           ▼
   Local Security AI (Ollama / Llama / Mistral / Qwen)
           │
           ├─ Alert Explainer
           ├─ Incident Investigation
           ├─ Why did risk increase?
           ├─ Risk evolution / trajectory
           └─ Response and mitigation recommendation
```

This is the pattern AHRAS follows:

- Deterministic + ML engines calculate risk
- Graph, hazard, and historical models provide evidence
- Local LLM converts evidence into human-readable investigation narratives
- The model remains optional and privacy-aware: sensitive telemetry stays local; summaries can still be exported to external APIs when allowed

### Five security jobs for the local model

1. Alert Explainer
   - Summarize why a risk score changed
   - Convert raw events into a clear analyst-facing explanation
   - Cite the main evidence: failed auth, IOC hit, historical incidents, graph proximity, asset relevance

2. Incident Investigation
   - Correlate alerts, IPs, users, hosts, and MITRE mappings
   - Produce a structured incident summary with severity, confidence, and likely attack path

3. Risk Increase Narrative
   - Answer “Why did my risk increase?” with a reasoned list of contributing factors
   - Make the XAI output readable for responders and managers

4. Risk Evolution / Threat Trajectory
   - Highlight how the risk curve changed over time
   - Explain whether risk velocity or acceleration is rising

5. Response Recommendation
   - Recommend containment, isolation, or investigation steps based on the evidence chain
   - Keep the final output grounded in AHRAS risk and graph data rather than free-form speculation

### Supported local AI workflow

The project already supports an optional OpenAI/Ollama-compatible local LLM endpoint via `AHRAS_LOCAL_LLM_URL` and `AHRAS_LOCAL_LLM_MODEL`.

```bash
# Example: local Ollama server
AHRAS_LOCAL_LLM_URL=http://localhost:11434/api/generate
AHRAS_LOCAL_LLM_MODEL=llama3
```

When set, AHRAS can generate a SOC-friendly narrative from a playbook or incident context. If no local model is available, the system falls back to a deterministic template so the pipeline remains stable and auditable. This keeps the architecture honest: the LLM explains evidence, but it does not replace the risk model.

### Enhanced Security Intelligence Features

AHRAS v6 includes advanced evidence analysis and threat assessment tools:

#### 1. **Confidence-Scored Evidence Chain with MITRE Mapping**
   - Each piece of evidence (failed auth, IOC hit, historical incident, graph proximity) is independently scored for confidence (0–100%)
   - All evidence is automatically mapped to MITRE ATT&CK techniques and tactics
   - Shows aggregate confidence across the entire evidence chain
   - API: `POST /api/v1/security/evidence-chain`

#### 2. **Asset Impact Assessment**
   - Identify and rank which critical systems (databases, domain controllers, file servers) are at risk from a threat source
   - Automatically score asset criticality and hops-away distance
   - Separate critical, high-risk, and low-risk assets with exposure summary
   - API: `POST /api/v1/security/asset-impact`

#### 3. **Threat Pattern–Specific Recommendations**
   - Generate tailored containment, isolation, and investigation steps based on the type of attack
   - Credential attacks: MFA, account lockout, password reset recommendations
   - Ransomware: system isolation, backup triggers, incident response activation
   - Lateral movement: network segmentation, privileged access monitoring
   - Automatic escalation to incident response team for CRITICAL threats
   - API: `POST /api/v1/security/threat-pattern`

#### 4. **Risk Component Deep-Dive**
   - Break down the final risk score into individual contributing factors (behavior anomaly, IOC match, historical threat, credential attempts, network exposure, protocol violations)
   - Show which engine produced each component (ML, Rules, Threat Intel)
   - Identify the dominant risk factor and top-3 contributors
   - API: `POST /api/v1/security/risk-components`

#### 5. **Live Incident Correlation**
   - Automatically find similar historical incidents from the same source IP
   - Determine if this is a known repeat offender or novel attack pattern
   - Show incident resolution methods from similar past cases
   - Calculate recurrence likelihood (HIGH/MEDIUM/LOW)
   - API: `POST /api/v1/security/incident-correlation`

#### 6. **Automated Response Recommendations**
   - Recommend security playbooks to execute (credential response, ransomware containment, lateral movement prevention, etc.)
   - Scale automation level from `observe` (logging) to `monitored` to `defensive` to `aggressive` (auto-block) based on severity
   - Suggest which playbooks can run without human approval vs. require analyst review
   - Estimate response time in minutes
   - API: `POST /api/v1/security/response-automation`

### Research angle

This gives AHRAS a stronger academic story than a simple chatbot wrapper:

- **Grounded security explanation** — all narratives cite actual AHRAS data sources
- **Evidence-based incident summaries** — confidence scoring shows signal strength
- **Privacy-preserving local inference** — sensitive telemetry never leaves the system
- **Explainable risk reasoning** — each component, asset, and recommendation is auditable
- **Adaptive, research-oriented SOC workflow** — analyst can drill down into any finding

## What's New in v6

| Module | Description |
|---|---|
| `rbac/` | 5 enterprise roles with granular permissions |
| `historical_risk/` | Repeat-offender memory — past incidents boost current score |
| `api/` | Clean `/api/v1/` external API layer |
| Threat Intel upgrade | Full OTX domain/IP + VirusTotal URL lookups added |

---

## Role Reference

| Role | Key Permissions |
|---|---|
| **Admin** | Everything |
| **SOC Analyst** | Alerts, Events, Cases, IOC, Threat Intel |
| **Threat Hunter** | Hunt, IOC, MITRE, TI, Risk Explain |
| **Incident Responder** | SOAR, Forensics, Cases, Assets |
| **Manager** | Dashboard, Reports, Read-only stats |

---

## External API v1

```
POST  /api/v1/logs         Submit raw logs
POST  /api/v1/events       Submit events to risk engine
POST  /api/v1/ioc          Add IOC
GET   /api/v1/alerts       List alerts
GET   /api/v1/cases        List cases
GET   /api/v1/risk         Risk score for IP
GET   /api/v1/threats      Threat hunt
GET   /api/v1/history      Historical risk data
GET   /api/v1/ti           Threat intel lookup
GET   /api/v1/rbac/roles   Role/permission matrix
GET   /api/v1/features     One-line description of every module (self-documenting)
POST  /api/v1/graph/predict-paths     Temporal-graph multi-hop attack path prediction
POST  /api/v1/soar/copilot/narrative  LLM (or template) incident note + exec summary

# Security Intelligence — Explanation & Threat Assessment
POST  /api/v1/security/alert-explainer          Why did a risk score change?
POST  /api/v1/security/investigate-incident     Structured incident summary with severity & confidence
POST  /api/v1/security/risk-increase            Ordered list of contributing factors
POST  /api/v1/security/risk-timeline            Velocity, acceleration, threat trajectory
POST  /api/v1/security/live-risk-timeline       Live risk trajectory from AHRAS history + graph
POST  /api/v1/security/counterfactual-risk      What if a blocking step had failed?
POST  /api/v1/security/evidence-chain           Confidence-scored evidence with MITRE mapping
POST  /api/v1/security/asset-impact             Critical assets at risk from source IP
POST  /api/v1/security/threat-pattern           Attack-specific containment recommendations
POST  /api/v1/security/risk-components          Deep-dive risk factor breakdown
POST  /api/v1/security/incident-correlation     Similar past incidents + recurrence risk
POST  /api/v1/security/response-automation      Recommended playbooks & automation level

POST  /api/v1/ztre/session            Continuous Zero-Trust session risk re-evaluation
GET   /api/v1/ztre/sessions           List active ZTRE session policies
POST  /api/v1/sigma/match             Match an event against loaded Sigma rules
GET   /api/v1/sigma/rules             List loaded Sigma rules
POST  /api/v1/threat-intel/stix/sync  Pull indicators from configured TAXII feed
GET   /api/v1/sensors/ebpf/status     eBPF kernel entropy monitor status
GET   /api/v1/health       System health
```

Auth: `Authorization: Bearer <token>` — get token from `POST /api/auth/login`

---

## IP Blocking — DISABLED BY DEFAULT

```ini
FIREWALL_ENABLED=false     # safe for personal laptops
AUTO_BLOCK_ENABLED=false
```

Only Admin can enable via Firewall tab.

---

## Phase 2 — Advanced Features (opt-in, off by default)

These run out of the box with a safe fallback, but need a bit of config to
use their real backing service:

```ini
# SOAR LLM Copilot — point at any local Ollama/OpenAI-compatible model.
# Without this set, /soar/copilot/narrative still works using a template.
AHRAS_LOCAL_LLM_URL=http://localhost:11434/api/generate
AHRAS_LOCAL_LLM_MODEL=llama3

# STIX/TAXII bulk threat feed ingestion. Without this set, /threat-intel/stix/sync
# is a safe no-op.
AHRAS_STIX_TAXII_URL=https://your-taxii-server/taxii/
AHRAS_STIX_COLLECTION_ID=your-collection-id
```

The temporal graph scorer (`graph/tgnn.py`), Zero-Trust risk engine
(`adaptive_learning/ztre.py`), Sigma rule engine (`detection/sigma_engine/`),
and deception feedback loop (`honeypot/deception_feedback.py`) need no
extra configuration — they run against the same in-process data the rest
of AHRAS already uses. The eBPF entropy monitor (`sensors/ebpf_monitor.py`)
needs Linux + root + `bcc` installed to use real kernel hooks; anywhere
else it automatically falls back to a fast polling-based monitor so
ransomware detection never silently stops working.

---

## Docs

- [FEATURES.md](FEATURES.md) — one-line-per-module cheat sheet (also live at `/api/v1/features`)
- [ARCHITECTURE.md](ARCHITECTURE.md) — module map and data flow  
- [INSTALLATION.md](INSTALLATION.md) — full setup for all platforms  
- [RESEARCH.md](RESEARCH.md) — academic context and contributions  
- Swagger UI: http://localhost:8000/docs (when running)
