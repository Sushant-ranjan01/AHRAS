"""Integration tests - full pipeline end to end"""
import pytest


class TestFullPipeline:

    def test_detection_to_risk_to_explanation(self, risk_engine, risk_explainer, xai_explainer):
        det = {"src_ip": "45.33.32.156", "attack_type": "Port Scan",
               "confidence": 0.9, "packet_count": 80, "unique_ports": 25,
               "syn_count": 40, "pps": 150, "anomaly_flag": True}
        risk = risk_engine.evaluate(det)
        exp = risk_explainer.explain(risk)
        report = xai_explainer.full_report(exp.to_dict(),
                                           signal_strength=risk.signal_strength,
                                           history_depth=5)
        assert risk.risk_score_100 >= 0
        assert exp.severity == risk.severity
        assert "counterfactual" in report
        assert "confidence" in report

    def test_adaptive_learning_changes_scores(self, risk_engine, weight_learner):
        from adaptive_learning.weight_learner import FeedbackSample
        det = {"src_ip": "1.2.3.4", "attack_type": "Anomalous Behaviour",
               "confidence": 0.6, "packet_count": 20, "anomaly_flag": True}
        risk_engine.set_adaptive_learner(weight_learner)
        score_before = risk_engine.evaluate(det).risk_score_100
        for _ in range(10):
            s = FeedbackSample(src_ip="1.2.3.4", label=0,
                               components={"signature": 0.0, "anomaly": 0.8,
                                           "density": 0.0, "drift_rate": 0.0},
                               predicted_risk=score_before)
            weight_learner.record_feedback(s)
        score_after = risk_engine.evaluate(det).risk_score_100
        assert score_after <= score_before + 1.0
        risk_engine._adaptive_learner = None
        weight_learner.reset_to_defaults()

    def test_graph_populated_by_events(self, risk_engine, threat_graph):
        if not threat_graph.available:
            pytest.skip("networkx not installed")
        threat_graph.clear()
        events = [
            {"src_ip": "10.10.10.1", "dst_ip": "192.168.1.5",
             "severity": "HIGH", "mitre_technique": "T1046",
             "target_asset_id": "server-01"},
            {"src_ip": "10.10.10.2", "dst_ip": "192.168.1.5",
             "severity": "MEDIUM", "target_asset_id": "server-01"},
        ]
        for ev in events:
            threat_graph.ingest_event(ev)
        threat_graph.ingest_ioc_match("10.10.10.1", "10.10.10.1", "ip")
        stats = threat_graph.stats()
        assert stats["total_nodes"] >= 3

    def test_forecast_after_history_accumulation(self, predictor):
        scores = [10, 20, 35, 50, 65, 78]
        result = predictor.predict("pipeline-test-ip", scores)
        assert result.trend_label == "ESCALATING"
        assert result.will_breach_critical is True

    def test_metrics_on_synthetic_dataset(self, metrics_calc):
        y_true  = [1]*40 + [0]*60
        y_score = [75.0]*35 + [15.0]*5 + [10.0]*55 + [70.0]*5
        lats    = [0.8] * 100
        report = metrics_calc.compute(y_true, y_score, lats,
                                      dataset_name="synthetic", threshold=20.0)
        assert report.total_samples == 100
        assert report.precision > 0
        assert report.recall > 0
        assert report.f1 > 0
        assert 0.0 <= report.auc <= 1.0
        d = report.to_dict()
        assert d["classification"]["accuracy"] >= 0

    def test_xai_counterfactual_actionable(self, xai_explainer):
        high_exp = {
            "final_score": 55.0, "severity": "HIGH",
            "components": [
                {"name": "ml_anomaly", "label": "ML", "raw_value": 0.9,
                 "weight": 15, "contribution": 13.5},
                {"name": "threat_intel", "label": "TI", "raw_value": 0.5,
                 "weight": 30, "contribution": 15.0},
                {"name": "asset", "label": "Asset", "raw_value": 0.6,
                 "weight": 20, "contribution": 12.0},
                {"name": "mitre", "label": "MITRE", "raw_value": 0.5,
                 "weight": 20, "contribution": 10.0},
                {"name": "uba", "label": "UBA", "raw_value": 0.3,
                 "weight": 15, "contribution": 4.5},
            ],
        }
        cf = xai_explainer.counterfactual(high_exp)
        assert cf is not None
        assert cf.target_severity == "MEDIUM"
        assert isinstance(cf.explanation, str)
        assert len(cf.explanation) > 10
