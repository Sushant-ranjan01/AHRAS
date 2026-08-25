"""Tests for adaptive_learning.weight_learner"""
import pytest
from adaptive_learning.weight_learner import (
    AdaptiveWeightLearner, FeedbackSample, DEFAULT_WEIGHTS, COMPONENT_KEYS
)


class TestAdaptiveLearner:
    def test_defaults_on_init(self, weight_learner):
        w = weight_learner.get_weights()
        for k in COMPONENT_KEYS:
            assert k in w

    def test_weights_sum_to_one(self, weight_learner):
        w = weight_learner.get_weights()
        assert abs(sum(w.values()) - 1.0) < 1e-6

    def test_tp_feedback_increases_high_contribution_weight(self):
        learner = AdaptiveWeightLearner(mongo_collection=None)
        initial = learner.get_weights()["signature"]
        s = FeedbackSample(src_ip="1.1.1.1", label=1,
                           components={"signature": 0.9, "anomaly": 0.0,
                                       "density": 0.0, "drift_rate": 0.0},
                           predicted_risk=50.0)
        learner.record_feedback(s)
        updated = learner.get_weights()["signature"]
        assert updated > initial, "TP feedback with high signature should increase sig weight"

    def test_fp_feedback_decreases_high_contribution_weight(self):
        learner = AdaptiveWeightLearner(mongo_collection=None)
        initial = learner.get_weights()["drift_rate"]
        s = FeedbackSample(src_ip="2.2.2.2", label=0,
                           components={"signature": 0.0, "anomaly": 0.0,
                                       "density": 0.0, "drift_rate": 0.9},
                           predicted_risk=75.0)
        learner.record_feedback(s)
        updated = learner.get_weights()["drift_rate"]
        assert updated < initial, "FP feedback with high drift_rate should decrease its weight"

    def test_weights_stay_normalized_after_update(self):
        learner = AdaptiveWeightLearner(mongo_collection=None)
        for _ in range(20):
            s = FeedbackSample(src_ip="3.3.3.3", label=1,
                               components={"signature": 0.8, "anomaly": 0.9,
                                           "density": 0.3, "drift_rate": 0.1},
                               predicted_risk=80.0)
            learner.record_feedback(s)
        w = learner.get_weights()
        assert abs(sum(w.values()) - 1.0) < 1e-4

    def test_no_weight_goes_below_min(self):
        from adaptive_learning.weight_learner import MIN_WEIGHT
        learner = AdaptiveWeightLearner(mongo_collection=None)
        for _ in range(100):
            s = FeedbackSample(src_ip="4.4.4.4", label=0,
                               components={"signature": 0.0, "anomaly": 0.0,
                                           "density": 0.0, "drift_rate": 1.0},
                               predicted_risk=90.0)
            learner.record_feedback(s)
        w = learner.get_weights()
        for k, v in w.items():
            assert v >= MIN_WEIGHT - 1e-6, f"Weight {k}={v} dropped below MIN_WEIGHT"

    def test_reset_restores_defaults(self):
        learner = AdaptiveWeightLearner(mongo_collection=None)
        s = FeedbackSample(src_ip="5.5.5.5", label=1,
                           components={"signature": 0.9, "anomaly": 0.0,
                                       "density": 0.0, "drift_rate": 0.0},
                           predicted_risk=70.0)
        learner.record_feedback(s)
        learner.reset_to_defaults()
        assert learner.get_weights() == DEFAULT_WEIGHTS
        assert learner._total_updates == 0

    def test_stats_tp_fp_counts(self):
        learner = AdaptiveWeightLearner(mongo_collection=None)
        for lbl in [1, 1, 0, 1, 0]:
            s = FeedbackSample(src_ip="6.6.6.6", label=lbl,
                               components={"signature": 0.5, "anomaly": 0.5,
                                           "density": 0.0, "drift_rate": 0.0},
                               predicted_risk=60.0)
            learner.record_feedback(s)
        stats = learner.stats()
        assert stats["true_positive_feedback"] == 3
        assert stats["false_positive_feedback"] == 2
        assert stats["total_updates"] == 5
