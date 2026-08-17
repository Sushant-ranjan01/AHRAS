# AHRAS — Installation Guide

## Requirements

| Item | Minimum | Recommended |
|---|---|---|
| OS | Ubuntu 20+, macOS 12+, Windows 10+ | Ubuntu 22.04 LTS |
| Python | 3.10 | 3.11 |
| RAM | 2 GB | 4 GB |
| Disk | 500 MB | 2 GB |
| Internet | Optional | For Threat Intel APIs |

---

## Linux / macOS Installation

```bash
# 1. Extract project
unzip AHRAS_v6_Complete.zip
cd AHRAS_v6/

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env with your preferred editor — API keys are optional

# 5. Start
python main.py
```

---

## Windows Installation

```powershell
# 1. Extract project (right-click → Extract All)
cd AHRAS_v6\

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure
copy .env.example .env

# 5. Start
python main.py
```

---

## Docker Installation

```bash
# Build and start
docker-compose up --build

# Run in background
docker-compose up -d

# Stop
docker-compose down
```

The docker-compose.yml mounts the project directory and exposes port 8000.

---

## Environment Configuration (.env)

```ini
# Server
HOST=0.0.0.0
PORT=8000

# SECURITY — keep these FALSE on personal machines
FIREWALL_ENABLED=false
AUTO_BLOCK_ENABLED=false
AUTO_BLOCK_RISK_THRESHOLD=9.0

# Threat Intelligence API Keys (all optional — system works without them)
ABUSEIPDB_KEY=           # https://www.abuseipdb.com/api
VIRUSTOTAL_KEY=          # https://www.virustotal.com/gui/my-apikey
OTX_KEY=                 # https://otx.alienvault.com/api

# JWT Security
JWT_SECRET=change-this-to-a-random-string-in-production

# Honeypot ports
HONEYPOT_SSH_PORT=2222
HONEYPOT_FTP_PORT=2121
HONEYPOT_HTTP_PORT=8081
```

---

## Default Users

| Username | Password | Role | Change After Install? |
|---|---|---|---|
| master | master123 | Admin | **YES — immediately** |

Create additional users via the Users tab (Admin only) or API:
```bash
curl -X POST http://localhost:8000/api/users \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst1","password":"strong-pass","role":"soc_analyst"}'
```

### Available Roles
- `admin` — full access
- `soc_analyst` — alerts, cases, events
- `threat_hunter` — hunting, IOC, TI
- `incident_responder` — SOAR, forensics
- `manager` — dashboard, reports

---

## Accessing the Threat Intel APIs

### AbuseIPDB (Free tier: 1000 lookups/day)
1. Register at https://www.abuseipdb.com
2. Go to API → Create Key
3. Add to .env: `ABUSEIPDB_KEY=your-key`

### VirusTotal (Free tier: 4 requests/min)
1. Register at https://www.virustotal.com
2. Go to Profile → API Key
3. Add to .env: `VIRUSTOTAL_KEY=your-key`

### AlienVault OTX (Free)
1. Register at https://otx.alienvault.com
2. Go to Settings → API Key
3. Add to .env: `OTX_KEY=your-key`

---

## Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx pytest-cov

# Run all tests
pytest tests/ -v

# IMPORTANT: Run firewall safety test first
pytest tests/test_firewall.py -v

# Run with coverage report
pytest tests/ --cov=. --cov-report=html
# Open htmlcov/index.html in browser
```

---

## Accessing the API Documentation

Swagger UI (interactive): http://localhost:8000/docs  
ReDoc (reference): http://localhost:8000/redoc

The `/api/v1/` external API endpoints are listed separately under the "External API v1" tag.

---

## Troubleshooting

**Port 8000 already in use:**
```bash
# Change port in .env: PORT=8001
# Or kill the process: kill $(lsof -ti:8000)
```

**Permission denied on packet capture (Linux):**
```bash
# Either run with sudo (not recommended for full system)
# Or use the FlowGenerator simulation mode (default)
# Live capture requires CAP_NET_RAW capability
```

**Honeypot port already in use:**
```bash
# Change honeypot ports in .env:
HONEYPOT_SSH_PORT=2223
HONEYPOT_FTP_PORT=2122
HONEYPOT_HTTP_PORT=8082
```

**Import error for win32evtlog (Linux/macOS):**
```
This is expected — WindowsLogCollector automatically falls back to
reading exported .log files from the logs/windows/ directory.
```
