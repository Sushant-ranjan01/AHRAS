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

## Docs

- [ARCHITECTURE.md](ARCHITECTURE.md) — module map and data flow  
- [INSTALLATION.md](INSTALLATION.md) — full setup for all platforms  
- [RESEARCH.md](RESEARCH.md) — academic context and contributions  
- Swagger UI: http://localhost:8000/docs (when running)
