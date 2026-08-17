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
