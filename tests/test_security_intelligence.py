from security_intelligence.engine import SecurityIntelligenceEngine


def test_alert_explainer_produces_evidence_chain():
    engine = SecurityIntelligenceEngine()
    result = engine.alert_explainer(
        alert_name="Multiple failed SSH logins",
        risk_score=82,
        evidence={
            "failed_logins": 47,
            "time_window_minutes": 3,
            "successful_login": True,
            "historical_incidents": 2,
            "ioc_match": False,
            "graph_proximity": "high",
        },
    )

    assert result["conclusion"]
    assert result["evidence"]["failed_logins"] == 47
    assert "failed logins" in result["conclusion"].lower()
    assert "raw_event_ids" in result["evidence"]


def test_investigate_incident_builds_summary():
    engine = SecurityIntelligenceEngine()
    summary = engine.investigate_incident(
        "10.10.14.27",
        {
            "alerts": ["Multiple failed SSH logins"],
            "related_ips": ["10.10.14.27", "192.168.1.14"],
            "related_users": ["alice"],
            "related_hosts": ["web-01", "db-01"],
            "mitre": ["T1110", "T1021", "T1078"],
            "risk_score": 91,
        },
    )

    assert summary["severity"] in {"CRITICAL", "HIGH", "MEDIUM"}
    assert summary["confidence"] >= 0
    assert summary["likely_attack"]
    assert "T1110" in summary["mitre_techniques"]


def test_risk_increase_explanation_has_breakdown():
    engine = SecurityIntelligenceEngine()
    summary = engine.explain_risk_increase(
        current_score=78,
        deltas=[
            {"label": "Repeated authentication failures", "value": 18},
            {"label": "Known malicious IOC", "value": 15},
            {"label": "Historical offender", "value": 13},
        ],
    )

    assert summary["risk_score"] == 78
    assert summary["reasons"][0]["label"] == "Repeated authentication failures"
    assert summary["total_contribution"] == 46


def test_risk_timeline_reports_velocity_and_acceleration():
    engine = SecurityIntelligenceEngine()
    timeline = engine.risk_timeline([35, 42, 58, 81])

    assert timeline["velocity"] in {"LOW", "MEDIUM", "HIGH"}
    assert timeline["acceleration"] in {"LOW", "MEDIUM", "HIGH"}
    assert timeline["threat_trajectory"] in {"STABLE", "ESCALATING", "CRITICAL"}
    assert len(timeline["points"]) == 4


def test_live_context_binds_to_ahras_data_sources():
    engine = SecurityIntelligenceEngine()

    class FakeHistory:
        def get_history_dict(self, indicator, indicator_type="ip"):
            return {
                "indicator": indicator,
                "incident_count": 3,
                "alert_count": 5,
                "threat_profile": "repeat offender",
                "days_since_last_seen": 2,
            }

    class FakeGraph:
        def blast_radius(self, ip, hops=2):
            return {
                "source_ip": ip,
                "total_reachable": 4,
                "assets_at_risk": ["asset:db-01"],
                "related_ips": ["10.0.0.82", "10.0.0.83"],
            }

    class FakeAlertMgr:
        def list_alerts(self, status_filter=None, limit=50):
            return [{"target_ip": "10.0.0.81", "title": "Repeated SSH failures", "severity": "HIGH"}]

    evidence = engine.build_live_alert_evidence(
        src_ip="10.0.0.81",
        alert_name="Multiple failed SSH logins",
        risk_score=82,
        hist_risk=FakeHistory(),
        threat_graph=FakeGraph(),
        alert_mgr=FakeAlertMgr(),
    )

    assert evidence["historical_incidents"] == 3
    assert evidence["graph_proximity"] == "high"
    assert evidence["related_ips"]


def test_live_risk_trajectory_uses_real_history():
    engine = SecurityIntelligenceEngine()

    class FakeHistory:
        def get_history(self, indicator, indicator_type="ip"):
            return type("H", (), {
                "recent_events": [
                    {"risk_score": 20},
                    {"risk_score": 31},
                    {"risk_score": 48},
                    {"risk_score": 79},
                ]
            })()

    class FakeGraph:
        def blast_radius(self, ip, hops=2):
            return {"source_ip": ip, "assets_at_risk": ["asset:db-01"], "related_ips": ["10.0.0.90"]}

    timeline = engine.build_live_risk_timeline("10.0.0.81", FakeHistory(), FakeGraph())

    assert timeline["velocity"] in {"MEDIUM", "HIGH"}
    assert timeline["threat_trajectory"] in {"ESCALATING", "CRITICAL"}
    assert timeline["assets_at_risk"] == ["asset:db-01"]


def test_counterfactual_analysis_uses_graph_impact():
    engine = SecurityIntelligenceEngine()

    class FakeGraph:
        def blast_radius(self, ip, hops=2):
            return {"source_ip": ip, "assets_at_risk": ["asset:db-01", "asset:ad-01"], "related_ips": ["10.0.0.90"]}

    result = engine.counterfactual_risk_analysis("10.0.0.81", "SSH", FakeGraph())

    assert result["estimated_impact"] in {"HIGH", "CRITICAL"}
    assert result["assets_at_risk"]
    assert "blocked_step" in result


def test_confidence_scored_evidence_chain_maps_mitre():
    """Test that evidence chain includes confidence scoring and MITRE mapping."""
    engine = SecurityIntelligenceEngine()
    
    result = engine.confidence_scored_evidence_chain(
        src_ip="10.0.0.81",
        context={
            "failed_logins": 15,
            "successful_login": True,
            "historical_incidents": 3,
            "ioc_match": True,
            "graph_proximity": "high",
        },
        risk_score=85.5,
    )
    
    assert result["source_ip"] == "10.0.0.81"
    assert result["aggregate_confidence"] >= 70
    assert result["chain_strength"] in {"STRONG", "MEDIUM", "WEAK"}
    assert len(result["evidence_chain"]) > 0
    # Check that evidence items have MITRE mapping
    evidence_items = result["evidence_chain"]
    assert any(e.get("mitre_technique") for e in evidence_items)
    assert any(e.get("mitre_tactic") for e in evidence_items)


def test_asset_impact_assessment_identifies_critical_systems():
    """Test that critical assets are properly identified and ranked."""
    engine = SecurityIntelligenceEngine()
    
    class FakeGraph:
        def blast_radius(self, ip, hops=3):
            return {
                "source_ip": ip,
                "assets_at_risk": ["ad-01", "db-prod-01", "fs-shared", "workstation-42"],
            }
    
    result = engine.asset_impact_assessment("10.0.0.81", FakeGraph())
    
    assert result["total_assets_at_risk"] >= 0
    assert result["critical_count"] >= 0
    assert result["moderate_count"] >= 0
    assert result["impact_level"] in {"CRITICAL", "HIGH", "LOW"}
    assert "db-prod-01" in [a["name"] for a in result["critical_assets"]] or result["critical_count"] >= 1


def test_threat_pattern_recommendations_are_attack_specific():
    """Test that recommendations change based on attack type."""
    engine = SecurityIntelligenceEngine()
    
    # Test credential attack recommendations
    cred_result = engine.threat_pattern_recommendations(
        src_ip="10.0.0.81",
        attack_type="Credential Abuse",
        severity="CRITICAL",
    )
    assert len(cred_result["detailed_recommendations"]) > 0
    assert len(cred_result["immediate_actions"]) > 0
    assert any("MFA" in rec or "password" in rec.lower() for rec in cred_result["detailed_recommendations"])
    
    # Test ransomware recommendations
    ransom_result = engine.threat_pattern_recommendations(
        src_ip="10.0.0.81",
        attack_type="Ransomware",
        severity="CRITICAL",
    )
    assert any("isolate" in rec.lower() for rec in ransom_result["detailed_recommendations"])


def test_risk_component_deep_dive_shows_contributing_factors():
    """Test that risk components are properly broken down."""
    engine = SecurityIntelligenceEngine()
    
    result = engine.risk_component_deep_dive(
        src_ip="10.0.0.81",
        risk_score=82.5,
        raw_components={
            "behavior_anomaly": 20,
            "ioc_match": 25,
            "historical_threat": 18,
            "credential_attempts": 22,
        }
    )
    
    assert result["final_risk_score"] == 82.5
    assert len(result["component_breakdown"]) > 0
    assert result["top_3_contribution"] > 0
    assert "dominant_risk_factor" in result
    # Check that components sum appropriately
    total_contrib = sum(c["contribution_to_risk"] for c in result["component_breakdown"])
    assert total_contrib > 0


def test_live_incident_correlation_finds_similar_incidents():
    """Test that similar historical incidents are found and correlated."""
    engine = SecurityIntelligenceEngine()
    
    class FakeHistory:
        def get_history_dict(self, ip, indicator_type="ip"):
            return {
                "incidents": [
                    {
                        "id": "INC-001",
                        "timestamp": 1000000,
                        "attack_type": "Credential Abuse",
                        "risk_score": 78,
                        "resolution": "Blocked",
                    },
                    {
                        "id": "INC-002",
                        "timestamp": 900000,
                        "attack_type": "Credential Abuse",
                        "risk_score": 75,
                        "resolution": "Monitored",
                    },
                ]
            }
    
    result = engine.live_incident_correlation(
        src_ip="10.0.0.81",
        attack_type="Credential Abuse",
        hist_risk=FakeHistory(),
    )
    
    assert result["source_ip"] == "10.0.0.81"
    assert len(result["similar_incidents"]) > 0
    assert result["same_attack_type_count"] >= 0
    assert result["recurrence_risk"] in {"HIGH", "MEDIUM", "LOW"}


def test_automated_response_recommendations_change_with_severity():
    """Test that response recommendations scale with threat severity."""
    engine = SecurityIntelligenceEngine()
    
    # Critical severity
    critical_result = engine.automated_response_recommendations(
        src_ip="10.0.0.81",
        severity="CRITICAL",
        risk_score=92,
        attack_type="Credential Abuse",
        asset_count=5,
    )
    assert critical_result["recommended_automation_level"] in {"aggressive", "defensive"}
    assert len(critical_result["suggested_playbooks"]) > 0
    
    # Low severity
    low_result = engine.automated_response_recommendations(
        src_ip="10.0.0.81",
        severity="LOW",
        risk_score=25,
        attack_type="Port Scan",
        asset_count=0,
    )
    assert low_result["recommended_automation_level"] in {"observe", "monitored"}
    
    # Critical should have fewer human approvals required
    assert critical_result.get("requires_human_approval", True) <= low_result.get("requires_human_approval", True)

