#!/usr/bin/env python3
"""
Demo script to show AHRAS AI security intelligence features in action.
This calls the actual security intelligence engine and prints results.
"""

from security_intelligence import SecurityIntelligenceEngine
import json

# Initialize the engine
engine = SecurityIntelligenceEngine()

print("=" * 80)
print("AHRAS AI SECURITY INTELLIGENCE ENGINE - LIVE DEMO")
print("=" * 80)

# Test 1: Confidence-Scored Evidence Chain with MITRE Mapping
print("\n[1] CONFIDENCE-SCORED EVIDENCE CHAIN WITH MITRE MAPPING")
print("-" * 80)
result = engine.confidence_scored_evidence_chain(
    src_ip="203.0.113.45",
    context={
        "failed_logins": 23,
        "successful_login": True,
        "historical_incidents": 4,
        "ioc_match": True,
        "graph_proximity": "high",
    },
    risk_score=88.5,
)
print(f"Source IP: {result['source_ip']}")
print(f"Risk Score: {result['risk_score']}")
print(f"Aggregate Confidence: {result['aggregate_confidence']}%")
print(f"Chain Strength: {result['chain_strength']}")
print(f"\nEvidence Items:")
for item in result["evidence_chain"]:
    print(f"  • {item['signal']}")
    print(f"    Confidence: {item['confidence']}% | MITRE: {item['mitre_technique']} ({item['mitre_tactic']})")
    print(f"    Severity: {item['severity']}")

# Test 2: Asset Impact Assessment
print("\n\n[2] ASSET IMPACT ASSESSMENT - WHICH CRITICAL SYSTEMS ARE AT RISK?")
print("-" * 80)
result = engine.asset_impact_assessment(src_ip="203.0.113.45")
print(f"Source IP: {result['source_ip']}")
print(f"Total Assets At Risk: {result['total_assets_at_risk']}")
print(f"Impact Level: {result['impact_level']}")
print(f"\nCritical Assets ({result['critical_count']}):")
for asset in result['critical_assets']:
    print(f"  ⚠️  {asset['name']} ({asset['type']}) - {asset['hops_away']} hops away")
print(f"\nHigh-Risk Assets ({result['moderate_count']}):")
for asset in result['moderate_assets']:
    print(f"  ⚡ {asset['name']} ({asset['type']}) - {asset['hops_away']} hops away")
print(f"\n{result['asset_exposure_summary']}")

# Test 3: Threat Pattern–Specific Recommendations
print("\n\n[3] THREAT PATTERN-SPECIFIC RECOMMENDATIONS")
print("-" * 80)
result = engine.threat_pattern_recommendations(
    src_ip="203.0.113.45",
    attack_type="Credential Abuse",
    severity="CRITICAL",
)
print(f"Attack Type: {result['attack_type']}")
print(f"Severity: {result['severity']}")
print(f"\nImmediate Actions (Top Priority):")
for i, action in enumerate(result['immediate_actions'], 1):
    print(f"  {i}. {action}")
print(f"\nDetailed Recommendations:")
for i, rec in enumerate(result['detailed_recommendations'], 1):
    print(f"  {i}. {rec}")
print(f"\nAutomation: {result['recommended_automation']}")
print(f"Time to Respond: {result['estimated_response_time_minutes']} minutes")

# Test 4: Risk Component Deep-Dive
print("\n\n[4] RISK COMPONENT DEEP-DIVE - WHY IS THE SCORE THIS HIGH?")
print("-" * 80)
result = engine.risk_component_deep_dive(
    src_ip="203.0.113.45",
    risk_score=88.5,
    raw_components={
        "behavior_anomaly": 18,
        "ioc_match": 28,
        "historical_threat": 22,
        "credential_attempts": 25,
        "network_exposure": 14,
    }
)
print(f"Final Risk Score: {result['final_risk_score']}/100")
print(f"Dominant Risk Factor: {result['dominant_risk_factor']}")
print(f"Top 3 Contribution: {result['top_3_contribution']} points ({result['top_3_summary']})")
print(f"\nComponent Breakdown:")
for comp in result['component_breakdown']:
    print(f"  • {comp['component']}")
    print(f"    Raw: {comp['raw_score']} | Weight: {comp['weight_percent']}% | Contribution: {comp['contribution_to_risk']} pts")
    print(f"    Source: {comp['engine']} | {comp['description']}")

# Test 5: Live Incident Correlation
print("\n\n[5] LIVE INCIDENT CORRELATION - KNOWN REPEAT OFFENDER?")
print("-" * 80)
result = engine.live_incident_correlation(
    src_ip="203.0.113.45",
    attack_type="Credential Abuse",
)
print(f"Source IP: {result['source_ip']}")
print(f"Current Attack Type: {result['current_attack_type']}")
print(f"Similar Historical Incidents: {result['incident_count']}")
print(f"Same Attack Type Count: {result['same_attack_type_count']}")
print(f"Recurrence Risk: {result['recurrence_risk']}")
print(f"\nPast Incidents:")
for inc in result['similar_incidents']:
    print(f"  • {inc['incident_id']} ({inc['days_ago']} days ago)")
    print(f"    Attack: {inc['attack_type']} | Risk: {inc['risk_score']}")
    print(f"    Resolution: {inc['resolution']}")
print(f"\n{result['correlation_summary']}")
print(f"Action: {result['suggested_escalation']}")

# Test 6: Automated Response Recommendations
print("\n\n[6] AUTOMATED RESPONSE RECOMMENDATIONS - WHAT SHOULD WE RUN?")
print("-" * 80)
result = engine.automated_response_recommendations(
    src_ip="203.0.113.45",
    severity="CRITICAL",
    risk_score=88.5,
    attack_type="Credential Abuse",
    asset_count=5,
)
print(f"Source IP: {result['source_ip']}")
print(f"Severity: {result['severity']}")
print(f"Risk Score: {result['risk_score']}")
print(f"Automation Level: {result['recommended_automation_level'].upper()}")
print(f"Can Auto-Execute: {'YES' if result['can_auto_execute'] else 'NO'}")
print(f"Requires Human Approval: {'YES' if result['requires_human_approval'] else 'NO'}")
print(f"\nSuggested Playbooks:")
for pb in result['suggested_playbooks']:
    print(f"  • {pb['name']}")
    print(f"    Actions: {', '.join(pb['actions'])}")
    print(f"    Time: {pb['estimated_time']}")
print(f"\nRemediation Steps:")
for step in result['remediation_steps']:
    print(f"  ✓ {step}")
print(f"\n{result['summary']}")

print("\n" + "=" * 80)
print("✅ All features working! This is the AI security intelligence layer in AHRAS.")
print("=" * 80)
