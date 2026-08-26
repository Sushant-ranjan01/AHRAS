# 🧠 AHRAS AI Security Intelligence — Where It Is & How To Check It

## 📍 File Locations

```
✅ security_intelligence/engine.py          [33 KB - Main AI logic]
✅ api/router.py                             [Added 6 new endpoints]
✅ tests/test_security_intelligence.py       [13 regression tests]
✅ demo_ai_security_intelligence.py          [Live demo script]
```

---

## 🔍 How To Verify It's Working

### **Option 1: Run The Tests** (Fastest)
```bash
cd AHRAS-new-18-08-26
py -m pytest tests/test_security_intelligence.py -v
```
**Result:** All 13 tests pass ✅

### **Option 2: Run The Demo** (See It In Action)
```bash
cd AHRAS-new-18-08-26
py demo_ai_security_intelligence.py
```
**Result:** Shows all 6 AI features working with live output

### **Option 3: Import & Call Directly** (In Python)
```python
from security_intelligence import SecurityIntelligenceEngine

engine = SecurityIntelligenceEngine()

# Feature 1: Confidence-scored evidence
result = engine.confidence_scored_evidence_chain(
    src_ip="203.0.113.45",
    context={...},
    risk_score=88.5
)
print(result['aggregate_confidence'])  # Shows 89.3%

# Feature 2: Asset impact
result = engine.asset_impact_assessment("203.0.113.45")
print(result['critical_assets'])  # Shows databases, domain controllers at risk

# Feature 3: Threat recommendations
result = engine.threat_pattern_recommendations(
    src_ip="203.0.113.45",
    attack_type="Credential Abuse",
    severity="CRITICAL"
)
print(result['immediate_actions'])  # Shows what to do NOW

# Feature 4: Risk breakdown
result = engine.risk_component_deep_dive(src_ip="203.0.113.45", risk_score=88.5)
print(result['dominant_risk_factor'])  # Shows "Known Malicious IOC"

# Feature 5: Repeat offender detection
result = engine.live_incident_correlation(
    src_ip="203.0.113.45",
    attack_type="Credential Abuse"
)
print(result['recurrence_risk'])  # Shows "HIGH" or "MEDIUM" or "LOW"

# Feature 6: Response automation
result = engine.automated_response_recommendations(
    src_ip="203.0.113.45",
    severity="CRITICAL",
    risk_score=88.5,
    attack_type="Credential Abuse",
    asset_count=5
)
print(result['suggested_playbooks'])  # Shows which playbooks to run
```

---

## 🌐 API Endpoints (When Server Running)

Start the server:
```bash
cd AHRAS-new-18-08-26
py main.py
```

Then call these endpoints:

```bash
# 1. Evidence chain with confidence & MITRE mapping
curl -X POST http://localhost:8000/api/v1/security/evidence-chain \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "203.0.113.45",
    "risk_score": 88.5,
    "failed_logins": 23,
    "successful_login": true,
    "historical_incidents": 4,
    "ioc_match": true,
    "graph_proximity": "high"
  }'

# 2. Asset impact assessment
curl -X POST http://localhost:8000/api/v1/security/asset-impact \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"src_ip": "203.0.113.45"}'

# 3. Threat-specific recommendations
curl -X POST http://localhost:8000/api/v1/security/threat-pattern \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "203.0.113.45",
    "attack_type": "Credential Abuse",
    "severity": "CRITICAL"
  }'

# 4. Risk component deep-dive
curl -X POST http://localhost:8000/api/v1/security/risk-components \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "203.0.113.45",
    "risk_score": 88.5,
    "raw_components": {
      "behavior_anomaly": 18,
      "ioc_match": 28,
      "historical_threat": 22,
      "credential_attempts": 25
    }
  }'

# 5. Incident correlation (repeat offender check)
curl -X POST http://localhost:8000/api/v1/security/incident-correlation \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "203.0.113.45",
    "attack_type": "Credential Abuse"
  }'

# 6. Response automation recommendations
curl -X POST http://localhost:8000/api/v1/security/response-automation \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "203.0.113.45",
    "severity": "CRITICAL",
    "risk_score": 88.5,
    "attack_type": "Credential Abuse",
    "asset_count": 5
  }'
```

---

## 📊 What Each Feature Does

| Feature | Purpose | Example Output |
|---------|---------|-----------------|
| **Confidence-Scored Evidence** | Score each piece of evidence & map to MITRE ATT&CK | Aggregate confidence: 89.3% \| MITRE: T1110.001 |
| **Asset Impact** | Find critical systems at risk | Critical: ad-01, db-prod-01 \| Count: 2 |
| **Threat Recommendations** | Attack-specific containment steps | Enable MFA, reset passwords, block IP |
| **Risk Deep-Dive** | Show which factors caused the score | "Known Malicious IOC" = 26.2% of risk |
| **Incident Correlation** | Detect repeat offenders | Recurrence risk: MEDIUM \| Past incidents: 2 |
| **Response Automation** | Recommend playbooks & automation level | Run "credential_attack_response" | Aggressive |

---

## 🔧 The Code Structure

```python
# Base evidence builder (original)
SecurityIntelligenceEngine.build_live_alert_evidence()

# Alert & investigation (original)
SecurityIntelligenceEngine.alert_explainer()
SecurityIntelligenceEngine.investigate_incident()

# Risk analysis (original)
SecurityIntelligenceEngine.explain_risk_increase()
SecurityIntelligenceEngine.risk_timeline()
SecurityIntelligenceEngine.build_live_risk_timeline()
SecurityIntelligenceEngine.counterfactual_risk_analysis()

# 🆕 NEW ENHANCED FEATURES (6 advanced analysis methods)
SecurityIntelligenceEngine.confidence_scored_evidence_chain()      # Confidence scoring + MITRE
SecurityIntelligenceEngine.asset_impact_assessment()               # Critical asset ranking
SecurityIntelligenceEngine.threat_pattern_recommendations()        # Attack-specific actions
SecurityIntelligenceEngine.risk_component_deep_dive()              # Risk factor breakdown
SecurityIntelligenceEngine.live_incident_correlation()             # Repeat offender detection
SecurityIntelligenceEngine.automated_response_recommendations()    # Playbook selection
```

---

## ✅ Verification Checklist

- [x] `security_intelligence/` directory exists with `engine.py`
- [x] 16 methods implemented in SecurityIntelligenceEngine
- [x] 6 new API endpoints added to `api/router.py`
- [x] All 13 regression tests pass
- [x] Demo script runs and shows all features working
- [x] README.md updated with feature documentation
- [x] FEATURES.md updated with module description

---

## 🎯 Key Differences From "Just An AI Chatbot"

This is **NOT** a simple LLM wrapper. Here's what makes it real:

1. **Grounded in deterministic evidence** — All outputs cite actual AHRAS data
2. **Confidence scoring** — Shows which signals are strong (90%+) vs weak
3. **MITRE mapping** — Every threat is linked to industry-standard framework
4. **Critical asset identification** — Shows what's actually at risk
5. **Repeat offender detection** — Learns from history
6. **Automated response** — Recommends specific playbooks to execute
7. **Multi-source integration** — Uses risk engine, graph, history, IOC, MITRE mapper
8. **Explainable reasoning** — Every recommendation has a justification

---

## 📝 Example: What The AI Returns

When analyzing IP `203.0.113.45` with risk score `88.5`:

```json
{
  "evidence_chain": [
    {
      "signal": "23 failed login attempts",
      "confidence": 95,
      "mitre_technique": "T1110.001",
      "severity": "HIGH"
    },
    {
      "signal": "Successful login after failed attempts",
      "confidence": 90,
      "mitre_technique": "T1078.003",
      "severity": "CRITICAL"
    }
  ],
  "critical_assets": ["ad-01", "db-prod-01"],
  "recommendations": [
    "Enable MFA for all user accounts",
    "Reset passwords for all accounts accessed from this IP"
  ],
  "dominant_risk_factor": "Known Malicious IOC",
  "recurrence_risk": "MEDIUM",
  "suggested_playbooks": ["credential_attack_response"],
  "automation_level": "aggressive"
}
```

This is a **research-grade security intelligence layer**, not a chatbot.

---

## 🚀 Next Steps

1. **Run the demo**: `py demo_ai_security_intelligence.py`
2. **Start the server**: `py main.py`
3. **Access via API**: Use the curl examples above
4. **Check the docs**: See README.md and FEATURES.md
5. **Explore the code**: Open `security_intelligence/engine.py`
