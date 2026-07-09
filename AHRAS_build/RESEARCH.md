# AHRAS — Research Document

## Title
**AHRAS: An Adaptive Hybrid Risk Assessment System with Explainable Scoring, Role-Based Access Control, and Historical Recidivism Modelling for Security Operations Centres**

---

## Abstract

AHRAS is a research-grade Security Information and Event Management (SIEM) and Security Orchestration, Automation and Response (SOAR) platform that addresses three under-solved problems in automated threat detection:

1. **The Black-Box Problem** — automated risk scores are shown without explanation, making them impossible to justify or tune.
2. **The Memoryless Scorer Problem** — most risk engines score each event in isolation, ignoring whether the same IP was involved in 15 previous incidents.
3. **The Access Control Gap** — most open-source SIEM tools implement only two roles (admin/user), lacking the granular role definitions used in real enterprise SOC teams.

AHRAS solves all three through: the Risk Explainer module (transparent 5-component score decomposition), the Historical Risk Engine (recidivism-based boost formula), and a 5-role RBAC system with 40+ granular permissions.

---

## Research Contributions

### Contribution 1 — Risk Explainer (Explainable AI for Security)

**Problem:** Commercial SIEM platforms (Splunk, QRadar, Microsoft Sentinel) produce risk scores as black boxes. Analysts cannot justify scores to managers, cannot identify which component is miscalibrated, and junior analysts cannot learn from unexplained numbers.

**Solution:** The RiskExplainer module decomposes every score into five labelled, weighted components:

| Component | Weight | Measures |
|---|---|---|
| Threat Intelligence | 30 pts | Is this IP/domain known-bad in external feeds? |
| Asset Criticality | 20 pts | How critical is the targeted asset? |
| MITRE Technique | 20 pts | Severity of the ATT&CK technique mapped to this event |
| UBA / Behaviour | 15 pts | Deviation from the user's established baseline |
| ML Anomaly | 15 pts | Isolation Forest anomaly score |

Each component reports its raw value, weight, contribution, utilisation percentage, a human-readable reason, and a technical detail string. Adjustments (trust reduction, multi-signal boost, cap) are each recorded with stated reasons. The output ends with a one-sentence verdict and ranked recommendations.

**Why This Matters:** This directly enables:
- Escalation justification ("The MITRE component scored 18/20 because the event maps to T1486 ransomware")
- System tuning ("The TI component is over-firing because our internal scanner is flagged — adjust trust score")
- Analyst training ("A score of 70 means HIGH severity driven primarily by repeated IOC matches")

**Comparison:**

| System | Explainable Score |
|---|---|
| Splunk Enterprise Security | No |
| IBM QRadar | No |
| Microsoft Sentinel | Partial (entity contributors named) |
| Wazuh | No |
| **AHRAS** | **Yes — full 5-component decomposition** |

---

### Contribution 2 — Historical Risk Engine (Recidivism-Based Scoring)

**Problem:** Most risk engines are memoryless. An IP that has been involved in 50 previous incidents receives the same initial score as a brand-new IP. This ignores a fundamental intuition: if an IP is a repeat offender, its current event is more likely to be malicious.

**Solution:** The HistoricalRiskEngine tracks every indicator (IP, domain, hash, username) across all AHRAS events, alerts, and cases. When the risk engine evaluates a new event, it queries the history:

```
incident_boost  = min(30, incident_count × 2)
alert_boost     = min(15, alert_count)
recency_factor  = 1.0 (< 7d) | 0.5 (7–30d) | 0.25 (> 30d)
history_boost   = (incident_boost + alert_boost) × recency_factor
```

**Example:** IP `10.0.0.5` has been involved in 15 incidents and 8 alerts, last seen 2 days ago:
```
incident_boost = min(30, 30) = 30
alert_boost    = min(15, 8)  = 8
recency_factor = 1.0
history_boost  = 38 pts
```

This boost is added to the base risk score before severity classification, meaning repeat offenders reliably score higher than first-time events with the same features.

**Why This Matters:**
- Reduces false negatives for repeat attackers
- Matches real analyst intuition (known-bad IPs should always score higher)
- Provides an audit trail of past involvement for any indicator

---

### Contribution 3 — Enterprise RBAC for Open-Source SIEM

**Problem:** Most open-source SIEM tools implement binary access control (admin vs user). Real SOC teams have specialised roles: Threat Hunters who need hunting and TI access but not SOAR execution; Managers who need dashboard visibility but not alert acknowledgement; Incident Responders who need SOAR but not firewall control.

**Solution:** AHRAS implements 5 enterprise roles with 40+ granular permissions:

| Role | Use Case | Key Permissions |
|---|---|---|
| Admin | System owner | Everything including firewall, user management |
| SOC Analyst | Daily alert triage | Alerts, events, cases, IOC, basic TI |
| Threat Hunter | Proactive hunting | Hunt execution, TI enrichment, risk explain |
| Incident Responder | Active incident handling | SOAR execution, forensics, case management |
| Manager | Oversight and reporting | Read-only dashboard, reports, risk trends |

Permissions are enforced via FastAPI dependency injection using the `require_permission(Perm.X)` factory, which produces a zero-boilerplate route-level guard that returns 403 with a descriptive message on failure.

---

## System Architecture Summary

AHRAS uses a layered architecture:

1. **Ingestion Layer** — PacketSniffer (live) or FlowGenerator (simulation)
2. **Feature Layer** — FeatureExtractor converts raw flows to ML feature vectors
3. **Detection Layer** — SignatureEngine (rules) + AnomalyDetector (Isolation Forest)
4. **Risk Layer** — RiskEngine (fusion) → HistoricalRiskEngine (boost) → RiskExplainer (decomposition)
5. **Context Layer** — MitreMapper + ThreatIntelManager (AbuseIPDB/VT/OTX) + IOCManager
6. **Response Layer** — CorrelationEngine → SOAREngine → FirewallManager (default OFF)
7. **Investigation Layer** — ThreatHunter + ForensicsManager + CaseManager
8. **Access Layer** — RBAC (5 roles, 40+ permissions) + JWT auth
9. **Integration Layer** — External API v1 (/api/v1/) for third-party systems

---

## Related Work

- **OSSIM** (AT&T Cybersecurity) — open-source SIEM, no explainability, complex setup
- **Wazuh** — agent-based SIEM, two roles only, no risk explanation
- **Zeek + ELK Stack** — powerful but requires multiple servers and expertise
- **RITA** (Real Intelligence Threat Analytics) — DNS/beaconing focus only
- **Snort/Suricata** — IDS only, no SIEM/SOAR features, no risk scoring

AHRAS is unique in combining: single-server deployment + ML detection + explainable scoring + historical memory + enterprise RBAC + SOAR automation + forensics workflow.

---

## Experimental Setup for Evaluation

To reproduce the detection accuracy claims:

```bash
# 1. Start AHRAS in simulation mode (FlowGenerator)
python main.py

# 2. Run the E2E test suite
pytest tests/test_e2e_simulation.py -v

# 3. Check detection rates for each attack type
pytest tests/test_detection.py -v --tb=short

# 4. Verify risk explainer consistency
pytest tests/test_risk_explainer.py -v

# 5. Generate coverage report
pytest tests/ --cov=. --cov-report=html
```

---

## Citation

If using AHRAS in academic work, please cite:

```
AHRAS: Adaptive Hybrid Risk Assessment System
Version 6.0, 2026
https://github.com/[your-repo]/ahras
Modules: Risk Explainer, Historical Risk Engine, RBAC, Threat Hunting,
         Forensics, Log Normalizer, Log Collectors
```
