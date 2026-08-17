# AHRAS v4 — Official Test Report

**Generated**: Automated pytest run
**Result**: ✅ 84/84 PASSED — 0 FAILED — 0 ERRORS
**Duration**: 1.42 seconds
**Python**: 3.12.3
**pytest**: 9.1.1

---

## Summary

| Module | Tests | Status |
|--------|-------|--------|
| Risk Engine (risk_scorer.py) | 10 | ✅ ALL PASSED |
| Adaptive Learning (weight_learner.py) | 8 | ✅ ALL PASSED |
| Temporal Prediction (predictor.py) | 11 | ✅ ALL PASSED |
| Graph Correlation (graph/engine.py) | 13 | ✅ ALL PASSED |
| Explainable AI (extended_explainer.py) | 11 | ✅ ALL PASSED |
| Metrics Calculator (metrics.py) | 10 | ✅ ALL PASSED |
| Dataset Loader (dataset_loader.py) | 7 | ✅ ALL PASSED |
| Risk Explainer (explainer.py) | 8 | ✅ ALL PASSED |
| Integration (full pipeline) | 6 | ✅ ALL PASSED |
| **TOTAL** | **84** | **✅ 84/84** |

---

## Detailed Results

### test_risk_engine.py (10/10)
- test_basic_evaluate_returns_result ✅
- test_external_malicious_scores_high ✅
- test_benign_local_scores_zero ✅
- test_severity_tiers_consistent ✅
- test_score_capped_at_100 ✅
- test_score_never_negative ✅
- test_private_ip_trust_is_high ✅
- test_raw_components_present ✅
- test_adaptive_weight_injection ✅
- test_mitre_boost_increases_score ✅

### test_adaptive_learning.py (8/8)
- test_defaults_on_init ✅
- test_weights_sum_to_one ✅
- test_tp_feedback_increases_high_contribution_weight ✅
- test_fp_feedback_decreases_high_contribution_weight ✅
- test_weights_stay_normalized_after_update ✅
- test_no_weight_goes_below_min ✅
- test_reset_restores_defaults ✅
- test_stats_tp_fp_counts ✅

### test_forecast.py (11/11)
- test_insufficient_data_returns_gracefully ✅
- test_escalating_series_detected ✅
- test_stable_series_detected ✅
- test_deescalating_series_detected ✅
- test_forecast_length_matches_horizon ✅
- test_forecast_values_bounded_0_100 ✅
- test_breach_detected_for_ramping_series ✅
- test_no_breach_for_low_series ✅
- test_top_escalating_ordering ✅
- test_confidence_increases_with_more_data ✅
- test_predict_from_events_dict ✅

### test_graph.py (13/13)
- test_graph_available ✅
- test_ingest_event_adds_nodes ✅
- test_ingest_event_adds_edges ✅
- test_shortest_path_exists ✅
- test_no_path_returns_none ✅
- test_blast_radius_includes_shared_asset ✅
- test_blast_radius_includes_mitre ✅
- test_campaign_clusters_two_attackers ✅
- test_centrality_returns_ranked_list ✅
- test_related_to_ioc ✅
- test_prune_stale_removes_nothing_fresh ✅
- test_clear_empties_graph ✅
- test_stats_type_counts ✅

### test_xai.py (11/11)
- test_counterfactual_for_critical ✅
- test_counterfactual_none_for_low ✅
- test_all_counterfactuals_walk_down_tiers ✅
- test_confidence_high_with_strong_signal ✅
- test_confidence_low_with_weak_signal ✅
- test_confidence_caveats_for_disagreeing_components ✅
- test_feature_importance_returns_ranked_list ✅
- test_feature_importance_empty_batch ✅
- test_full_report_has_all_keys ✅
- test_counterfactual_component_in_explanation ✅
- test_counterfactual_required_contrib_less_than_current ✅

### test_evaluation.py (10/10)
- test_perfect_classifier_metrics ✅
- test_all_wrong_classifier ✅
- test_confusion_matrix_adds_up ✅
- test_auc_near_one_for_perfect_classifier ✅
- test_auc_near_zero_for_inverted_classifier ✅
- test_latency_stats_computed ✅
- test_roc_curve_present ✅
- test_per_class_breakdown ✅
- test_empty_input_returns_zero_report ✅
- test_to_dict_has_all_keys ✅

### test_dataset_loader.py (7/7)
- test_cicids_detection ✅
- test_generic_csv_detection ✅
- test_limit_respected ✅
- test_record_has_required_fields ✅
- test_benign_tokens_map_to_zero ✅
- test_from_folder_finds_csvs ✅
- test_from_folder_empty_raises ✅

### test_risk_explainer.py (8/8)
- test_explain_returns_explanation ✅
- test_severity_matches_engine ✅
- test_benign_local_scores_zero ✅
- test_components_list_not_empty ✅
- test_each_component_has_required_fields ✅
- test_threat_intel_not_fabricated_for_local ✅
- test_to_dict_serialisable ✅
- test_full_pipeline_critical_attack ✅

### test_integration.py (6/6)
- test_detection_to_risk_to_explanation ✅
- test_adaptive_learning_changes_scores ✅
- test_graph_populated_by_events ✅
- test_forecast_after_history_accumulation ✅
- test_metrics_on_synthetic_dataset ✅
- test_xai_counterfactual_actionable ✅

---

## Bugs Found and Fixed During Testing

| # | File | Bug | Fix |
|---|------|-----|-----|
| 1 | risk_explainer/explainer.py | ThreatIntel fallback used `1-trust_score`, so any unknown domain (trust=0.4) generated fake TI evidence scoring 18/30 pts | Fixed: only trust ≤ 0.15 (unresolvable) gets a fallback signal |
| 2 | risk_explainer/explainer.py | Signature score was halved (`sig_factor * 0.5`) before blending, so a 90% confident signature match only contributed as 45% | Fixed: full signature confidence used |
| 3 | xai/extended_explainer.py | Confidence labelled MEDIUM even with signal_strength=1 and history_depth=0 because high signal_agreement overrode weak data | Fixed: hard cap at LOW when signal_strength < 2 or history_depth == 0 |

---

## What Is Complete

### Application (all previously working)
- ✅ FastAPI SOC dashboard on http://127.0.0.1:8000
- ✅ MongoDB persistence (AHRAS_DB)
- ✅ Live packet capture (Scapy)
- ✅ Hybrid detection (Signature + ML IsolationForest)
- ✅ SOAR automation with per-IP cooldown
- ✅ Private IP noise filtering
- ✅ IOC management, Cases, Alerts, Correlation
- ✅ Forensics, UBA, Threat Intel, Honeypot
- ✅ Firewall (dry-run mode on laptop)
- ✅ Reports, Assets, RBAC

### Phase 1 Research Modules (new)
- ✅ Module 1: Adaptive Risk Weight Learning (`adaptive_learning/`)
- ✅ Module 2: Temporal Attack Prediction (`forecast/`)
- ✅ Module 3: Graph-based Threat Correlation (`graph/`)
- ✅ Module 4: Explainable AI extension (`xai/`)

### Evaluation Harness (new)
- ✅ Dataset loader: CICIDS2017, NSL-KDD, UNSW-NB15, generic CSV
- ✅ Metrics calculator: all 11 metrics (Accuracy, Precision, Recall, F1, ROC, AUC, FPR, Detection Rate, Latency, CPU, Memory)
- ✅ CLI runner: `python -m evaluation.runner --dataset <path>`

### Testing
- ✅ 84 automated tests — 84/84 passing
- ✅ pytest.ini configuration
- ✅ TESTING_GUIDE.md — complete guide

### Documentation
- ✅ TESTING_GUIDE.md
- ✅ IEEE_PAPER_DRAFT.md — full paper draft (fill in your actual eval numbers)
- ✅ TEST_REPORT.md (this file)

---

## What You Need To Do

1. **Download a dataset** (CICIDS2017 or NSL-KDD — links in TESTING_GUIDE.md)
2. **Run the evaluation harness**:
   ```
   python -m evaluation.runner --dataset /path/to/data.csv --limit 10000 --output results/eval.json
   ```
3. **Fill in the X.XXX values** in IEEE_PAPER_DRAFT.md with your actual numbers
4. **Generate the ROC curve plot** using the Python snippet in TESTING_GUIDE.md Section 5
5. **Run the adaptive learning convergence demo** (Section 4 of TESTING_GUIDE.md) and screenshot for the paper
6. **Submit the paper** — the draft is structured for IEEE conference format (~4200 words)
