# AHRAS — Adaptive Hybrid Risk Assessment System
### Version 6.0 · Python 3.11 · FastAPI · Machine Learning · SIEM/SOAR

AHRAS is a full-stack, open-source **SIEM/SOAR** platform built for researchers, students, and SOC analysts. It detects threats via a dual signature+ML pipeline, explains every risk score in human-readable terms, tracks repeat offenders through historical memory, and runs entirely on a single laptop.

---

## Quick Start

```bash
unzip AHRAS_v6_Complete.zip && cd AHRAS_v6/
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # Set SECRET_KEY, MONGO_URI, etc — see below
python main.py                # Start server
# Open http://localhost:8000
```

**Default login:** `admin / Admin@123` (also `analyst / Analyst@123`, `manager / Manager@123` —
seeded in `auth/manager.py`). **Change these before exposing the app to anyone else** — see
"Before you run this" below.

See **PRE-RUN CHECKLIST** below for everything to set up first (Mongo, `.env`, and — if you
want the Local Security AI layer to actually narrate with a model instead of templates —
Ollama).

---

## New: Dark/Light Mode + AI Summarizer (Dashboard)

- **Dark/Light mode** — toggle button in the sidebar (next to the notification bell). Preference
  saved in the browser (`localStorage`) and respected on next visit; defaults to the OS-level
  `prefers-color-scheme` if nothing's saved yet. Every existing panel repaints automatically —
  it's a CSS-variable swap, not a second stylesheet, so nothing needed touching per-panel.
- **Sidebar layout fix** — the sidebar is now `position:fixed` (was `sticky` inside a flex row,
  which silently breaks once `overflow-x:hidden` is set on `html`/`body` — the sidebar would
  render its own height and then just stop while the page kept scrolling underneath it). It now
  spans the full viewport height for the entire scroll, on any page length.
- **AI Summarizer** — new card at the top of the Dashboard tab ("🤖 AI Summary — In Plain
  English"). Answers, for someone with zero security background: *what's happening*, *why*, and
  *what (if anything) they need to do*. Always grounded in the same live numbers as the rest of
  the dashboard (alert counts, severities, top source, blocked IPs) — never invents figures.
  Backed by `GET /api/summary/plain-english` → `SecurityIntelligenceEngine.plain_english_summary()`.
  Works out of the box with a deterministic template; if Ollama is configured (see checklist
  below), it hands those same grounded facts to the local model for a more natural write-up
  instead — the card shows which one generated it.

---

## Platform Security Hardening (Application Security, not Detection)

There are two different security stories in AHRAS: whether it *detects attackers on your
network* (it does — that's the core IDS/risk engine), and whether *AHRAS itself* can be
attacked as a web application. This section is the second one.

- **Every `/api/v1/*` endpoint now requires a valid JWT.** Previously the entire external API
  (32 endpoints — submit events, add IOCs, sync STIX feeds, update ZTRE session risk, etc.) had
  no authentication at all; anyone who knew or guessed a URL could call it.
- **The RBAC permission system (`rbac/permissions.py`) is now actually enforced**, not just
  exposed as a self-check endpoint. State-changing routes require specific permissions —
  `POST /api/v1/ioc` requires `IOC_WRITE`, `/logs` and `/events` require `NORMALIZER_USE`,
  STIX sync requires `TI_ENRICH` — none of which the seeded ANALYST role has, so a normal
  analyst account is now read-only against these by design, not by convention.
  `/api/v1/ztre/session` (can restrict/revoke a live session) is master-only.
- **Audit logging** on every state-changing `/api/v1` route (`ahras.audit` logger — who, what,
  when).
- **CORS is no longer wildcard-open.** Set `ALLOWED_ORIGINS` in `.env` (comma-separated) before
  deploying; defaults to localhost-only in `DEBUG=true`, rejects everything cross-origin if
  unset in production.
- **Brute-force lockout**: 5 failed logins for a username locks it for 15 minutes, independent
  of whether a later attempt has the right password.
- **Forced password change for seeded accounts** — `admin`, `analyst`, `manager` are flagged
  `must_change_password`. The dashboard shows a change-password modal right after login for
  these accounts (dismissible, but it'll reappear next login until changed). New endpoint:
  `POST /api/auth/change-password`.

---

## PRE-RUN CHECKLIST

Do these **before** `python main.py` / `docker-compose up`:

1. **MongoDB running.** `MONGO_URI` (default `mongodb://localhost:27017`) must point at a
   reachable Mongo instance, or AHRAS silently falls back to in-memory storage (fine for a
   quick demo, not for anything you want to persist or evaluate). Either install Mongo locally,
   or use `docker-compose up mongo` (now included in `docker-compose.yml`).
2. **`.env` filled in.**
   ```bash
   cp .env.example .env
   ```
   At minimum set:
   - `SECRET_KEY` — generate one: `python -c "import secrets; print(secrets.token_hex(32))"`.
     **Required if `DEBUG=false`** — the app now refuses to boot on the placeholder key outside
     debug mode (see `config/settings.py`). In `DEBUG=true` it auto-generates a throwaway key
     and warns, but sessions won't survive a restart.
   - `MONGO_URI`, `MONGO_DB`
   - `ABUSEIPDB_KEY` / `VIRUSTOTAL_KEY` / `OTX_KEY` — optional, only needed for live threat-intel
     enrichment.
   - `ALLOWED_ORIGINS` — comma-separated frontend origins for CORS. Skip this for local dev
     (defaults to localhost); **required** before deploying anywhere else, or the dashboard's
     API calls will be rejected by the browser.
3. **Change the seeded default passwords** (`admin/Admin@123`, `analyst/Analyst@123`,
   `manager/Manager@123`) before this is reachable by anyone but you.
4. **(Optional) Ollama, for real LLM narration instead of templates.** The SOAR copilot and the
   Local Security AI layer (alert explainer, incident investigation) both work out of the box
   with deterministic templates — nothing breaks if you skip this. But if you want the actual
   local-model narration the README/RESEARCH.md describe:
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh   # or: docker-compose up -d ollama
   ollama pull llama3                              # or: docker exec -it ahras-ollama ollama pull llama3
   export AHRAS_LOCAL_LLM_URL=http://localhost:11434/api/generate
   export AHRAS_LOCAL_LLM_MODEL=llama3
   ```
   Add the same two `AHRAS_LOCAL_LLM_*` vars to `.env` so they persist. Check it's wired up:
   `GET /api/v1/soar/copilot` responses and `/api/v1/security/alert-explainer` responses both
   include `"llm_configured": true` and `"generated_by": "local-llm:llama3"` once this is live;
   until then they report `"generated_by": "template"` — that's expected, not broken.
5. **Run the test suite once** to confirm your environment is sane: `pytest -q` (171 tests as of
   this build).
6. **Before citing evaluation numbers in a paper:** re-run `evaluation/runner.py`. It previously
   derived its "anomaly" signal from the dataset's ground-truth label (`record.label == 1`),
   which leaks the answer into the score and inflates recall/AUC. This has been fixed to use a
   blind, feature-only heuristic (`_statistical_anomaly_flag`) instead — your recall/AUC numbers
   will now be lower and honest. Re-generate any report/slide numbers pulled from the old runs.

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
