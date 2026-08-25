# AHRAS Feature Reference

One line per module — what it does and nothing more. For deeper detail see
[ARCHITECTURE.md](ARCHITECTURE.md). This same list is also served live at
`GET /api/v1/features` so it never goes stale.

| Module | What it does |
|---|---|
| `sensors/` | Live packet capture and network flow generation. |
| `collectors/` | Pulls logs from OS and application sources (Windows, Linux, Apache). |
| `normalizer/` | Converts logs from different sources into a single unified event schema. |
| `feature_engineering/` | Converts raw network/log events into numeric features for the ML models. |
| `detection/signature_engine/` | Rule/signature-based detection for known attack patterns. |
| `detection/anomaly_engine/` | ML-based anomaly detector trained on normal traffic baselines. |
| `detection/virus_engine/` | Signature-based malware/virus detection. |
| `detection/ransomware_engine/` | Detects ransomware-like behavior (rapid file encryption patterns). |
| `detection/` | Combines signature and ML anomaly detection into one hybrid engine. |
| `risk_engine/` | Combines detection signals into a single 0–100 risk score with severity rating. |
| `historical_risk/` | Remembers past incidents per indicator so repeat offenders score higher over time. |
| `risk_explainer/` | Turns a raw risk score into a human-readable explanation of why it was assigned. |
| `security_intelligence/` | Enhanced threat analysis: confidence-scored evidence chains with MITRE mapping, asset impact assessment, attack-specific recommendations, risk component deep-dive, incident correlation, and automated response playbooks. |
| `xai/` | Extended explainability for ML detections (feature attribution). |
| `adaptive_learning/` | Learns and tunes risk-scoring weights from analyst feedback over time. |
| `forecast/` | Predicts near-future risk trends from historical event data. |
| `mitre/` | Maps detected attack behavior to MITRE ATT&CK technique IDs. |
| `correlation/` | Links related alerts/events into a single incident narrative. |
| `graph/` | Builds an entity relationship graph (IPs, users, assets) for pivoting. |
| `uba/` | User Behavior Analytics — baselines normal user activity and flags deviations. |
| `threat_intel/` | Looks up indicators against AbuseIPDB, VirusTotal, OTX, and a local intel DB. |
| `ioc_management/` | Stores and matches Indicators of Compromise (IPs, domains, hashes, URLs). |
| `threat_hunting/` | Proactive search across alerts, cases, IOCs, and threat intel for one indicator. |
| `alerts/` | Creates, stores, and manages security alerts raised by the detection pipeline. |
| `case_management/` | Tracks investigation cases: creation, status, notes, linked alerts. |
| `forensics/` | Deeper investigation tooling for confirmed incidents (timeline, artifacts). |
| `soar/` | Runs automated response playbooks on alerts (Security Orchestration & Response). |
| `response_engine/` | Executes automated or analyst-triggered response actions to threats. |
| `firewall/` | Optional IP blocking/allow-listing — **disabled by default** for safety. |
| `honeypot/` | Decoy SSH/FTP/HTTP services that lure and log attacker activity. |
| `asset_management/` | Tracks known hosts/assets and their criticality for risk weighting. |
| `event_management/` | Central event bus/store for all normalized security events. |
| `auth/` | Login, JWT tokens, and user identity. |
| `rbac/` | Role-based access control — 5 roles, granular permissions, route guards. |
| `api/` | External REST API layer (`/api/v1`) for integrations and third-party tools. |
| `dashboard/` | Web UI served at `/` — the analyst-facing view of all of the above. |
| `reporting/` | Generates PDF/HTML incident and summary reports from alerts and cases. |
| `evaluation/` | Loads benchmark datasets and scores detection accuracy (precision/recall/F1). |
| `database/` | Persistence layer — MongoDB-backed, falls back to in-memory if unavailable. |
| `maintenance/` | Backup, restore, cleanup, and delete utilities for stored data. |
| `utils/` | Shared helpers, including IP/data enrichment. |
| `config/` | Central app configuration, loaded from environment variables and `.env`. |

## Phase 2 additions (novel / structural)

| Module | What it does |
|---|---|
| `graph/tgnn.py` | Time-decayed graph embeddings that score multi-hop attack paths as they develop — a lightweight, dependency-free stand-in for a trained Temporal GNN (see file docstring for exact scope). |
| `soar/copilot.py` | Turns a SOAR playbook run into an analyst note + plain-language exec summary. Uses a local LLM (Ollama/OpenAI-compatible, e.g. Llama 3 or Mistral) if `AHRAS_LOCAL_LLM_URL` is set, else a safe template fallback. |
| `security_intelligence/engine.py` | Grounded security intelligence layer: confidence-scored evidence chains with MITRE mapping, asset criticality assessment, attack-pattern-specific recommendations, risk factor deep-dive, historical incident correlation with recurrence risk, and automated response playbook selection. All outputs remain grounded in deterministic AHRAS data (risk engine, graph, history) rather than free-form LLM speculation. |
| `adaptive_learning/ztre.py` | Zero-Trust Continuous Adaptive Risk Engine — shrinks session TTL/scope (or revokes) the moment a session's risk score spikes, instead of waiting for the token to expire. |
| `sensors/ebpf_monitor.py` | Kernel-level file-write entropy monitoring via eBPF (bcc) for near-instant ransomware detection; falls back to tight userspace polling when eBPF/root isn't available. |
| `honeypot/deception_feedback.py` | Extracts TTPs from live honeypot hits, auto-generates a Sigma rule from the pattern, and pushes the source IP straight to the firewall. |
| `detection/sigma_engine/` | Loads and matches standard Sigma YAML detection rules (community format) against normalized events, independent of the hand-written signature engine. |
| `threat_intel/stix_ingestor.py` | Bulk-pulls STIX 2.x `indicator` objects from a TAXII 2.1 feed straight into the IOC manager. |
| `.github/workflows/ci.yml` | GitHub Actions pipeline — runs `pytest` and a `bandit` security lint on every push/PR. |
