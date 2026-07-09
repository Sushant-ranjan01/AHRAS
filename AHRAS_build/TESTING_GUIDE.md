# AHRAS v4 — Complete Testing Guide

## Overview
This guide covers how to run and interpret every test in AHRAS v4,
including the automated pytest suite, the public-dataset evaluation
harness, and manual verification steps for each research module.

---

## 1. Environment Setup

```bash
# 1. Install all dependencies (run once)
pip install -r requirements.txt
pip install pytest pytest-cov

# 2. Start MongoDB (required for the app; NOT required for tests)
# Tests run entirely without MongoDB using mocks.

# 3. Verify setup
python -m pytest tests/ --collect-only
# Should show 84 tests across 7 files
```

---

## 2. Running the Automated Test Suite

### Run everything
```bash
cd AHRAS_fixed
python -m pytest tests/ -v
```
Expected: **84 passed** in under 5 seconds.

### Run with coverage report
```bash
python -m pytest tests/ -v --cov=. --cov-report=term-missing \
  --cov-omit="tests/*,*/migrations/*"
```

### Run a single module
```bash
python -m pytest tests/test_risk_engine.py -v        # Risk engine (10 tests)
python -m pytest tests/test_adaptive_learning.py -v  # Adaptive learning (8 tests)
python -m pytest tests/test_forecast.py -v           # Temporal prediction (11 tests)
python -m pytest tests/test_graph.py -v              # Graph correlation (13 tests)
python -m pytest tests/test_xai.py -v                # Explainable AI (11 tests)
python -m pytest tests/test_evaluation.py -v         # Metrics calculator (10 tests)
python -m pytest tests/test_dataset_loader.py -v     # Dataset loader (7 tests)
python -m pytest tests/test_risk_explainer.py -v     # Risk explainer (8 tests)
python -m pytest tests/test_integration.py -v        # End-to-end (6 tests)
```

### Test suite structure

| File | Module Under Test | Tests |
|------|------------------|-------|
| test_risk_engine.py | risk_engine.risk_scorer | 10 |
| test_adaptive_learning.py | adaptive_learning.weight_learner | 8 |
| test_forecast.py | forecast.predictor | 11 |
| test_graph.py | graph.engine | 13 |
| test_xai.py | xai.extended_explainer | 11 |
| test_evaluation.py | evaluation.metrics | 10 |
| test_dataset_loader.py | evaluation.dataset_loader | 7 |
| test_risk_explainer.py | risk_explainer.explainer | 8 |
| test_integration.py | Full pipeline | 6 |
| **Total** | | **84** |

---

## 3. Public Dataset Evaluation

### Step 1: Download a dataset

**CICIDS2017** (recommended — most cited in IDS papers):
```
https://www.unb.ca/cic/datasets/ids-2017.html
Download: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv (or any day file)
Size: ~250 MB per file
```

**NSL-KDD** (classic benchmark):
```
https://www.unb.ca/cic/datasets/nsl.html
Download: KDDTrain+.txt and KDDTest+.txt
Size: ~18 MB each
```

**UNSW-NB15**:
```
https://research.unsw.edu.au/projects/unsw-nb15-dataset
Download: UNSW_NB15_training-set.csv
Size: ~85 MB
```

### Step 2: Run evaluation

```bash
# CICIDS2017 — single file, 10,000 samples
python -m evaluation.runner \
  --dataset /path/to/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv \
  --limit 10000 \
  --threshold 20 \
  --output results/cicids2017_eval.json

# NSL-KDD
python -m evaluation.runner \
  --dataset /path/to/KDDTrain+.txt \
  --limit 10000 \
  --threshold 20 \
  --output results/nslkdd_eval.json

# UNSW-NB15
python -m evaluation.runner \
  --dataset /path/to/UNSW_NB15_training-set.csv \
  --limit 10000 \
  --threshold 20 \
  --output results/unsw_eval.json

# Entire folder of CICIDS2017 day-files
python -m evaluation.runner \
  --dataset /path/to/cicids_folder/ \
  --limit 5000 \
  --output results/cicids_full.json
```

### Step 3: Interpret results

The JSON output contains all 11 metrics:

```json
{
  "classification": {
    "accuracy":            0.9234,   // (TP+TN) / total
    "precision":           0.9101,   // TP / (TP+FP) — how reliable are alerts?
    "recall":              0.9456,   // TP / (TP+FN) — how many attacks detected?
    "f1":                  0.9275,   // harmonic mean of precision & recall
    "auc":                 0.9612,   // area under ROC curve (1.0 = perfect)
    "false_positive_rate": 0.0812,   // FP / (FP+TN) — false alarm rate
    "detection_rate":      0.9456    // = recall, attacks correctly detected
  },
  "performance": {
    "mean_latency_ms":   0.42,     // average time to score one event
    "p95_latency_ms":    0.91,     // 95th percentile latency
    "p99_latency_ms":    1.23,     // 99th percentile latency
    "throughput_eps":    2381.0,   // events processed per second
    "peak_memory_mb":    184.0,    // peak RAM during evaluation
    "mean_cpu_pct":      12.4      // average CPU usage %
  }
}
```

### Threshold tuning

The `--threshold` flag sets the risk score cutoff for classifying an event as an attack.
Default is 20 (any risk_score_100 >= 20 = attack prediction).

| Threshold | Effect |
|-----------|--------|
| 10 | Higher recall, higher FPR (catches more attacks, more false alarms) |
| 20 | Balanced (recommended default) |
| 50 | Higher precision, lower recall (fewer false alarms, misses more attacks) |
| 70 | Very high precision only (only flag near-certain attacks) |

Run with multiple thresholds to build the full precision-recall curve:
```bash
for t in 10 20 30 50 70; do
  python -m evaluation.runner --dataset /path/to/data.csv \
    --limit 5000 --threshold $t \
    --output results/eval_threshold_${t}.json
done
```

---

## 4. Manual Module Testing

### Module 1: Adaptive Risk Weight Learning

```bash
# Start the app
python main.py

# 1. Check initial weights
curl http://127.0.0.1:8000/api/adaptive-learning/stats

# 2. Generate some traffic, let SOAR create cases
# 3. In the dashboard Cases tab, close a case as FALSE_POSITIVE
# 4. Check weights shifted:
curl http://127.0.0.1:8000/api/adaptive-learning/stats

# 5. Force a manual labeled sample (no traffic needed):
curl -X POST http://127.0.0.1:8000/api/adaptive-learning/feedback \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"src_ip":"1.2.3.4","label":0,"components":
       {"signature":0.0,"anomaly":0.9,"density":0.0,"drift_rate":0.0},
       "predicted_risk":75}'

# 6. Check convergence curve (for paper plot):
curl http://127.0.0.1:8000/api/adaptive-learning/convergence
```

**What to verify:**
- `total_updates` increments on each case closure or manual feedback
- `drift_from_default` shows non-zero values after several FP feedbacks
- `weights` always sum to 1.0 (verify: add all 4 values)

---

### Module 2: Temporal Attack Prediction

```bash
# After running the app for a few minutes with traffic:

# Forecast for a specific IP (needs 3+ events in history)
curl http://127.0.0.1:8000/api/forecast/45.33.32.156

# Top 10 escalating IPs right now
curl http://127.0.0.1:8000/api/forecast/escalating/top?n=10

# Fleet-wide summary
curl http://127.0.0.1:8000/api/forecast/fleet
```

**What to verify:**
- `trend_label` is one of ESCALATING / STABLE / DE-ESCALATING / INSUFFICIENT_DATA
- `forecast_next` contains exactly 5 values all in [0, 100]
- IPs with growing risk_score history appear in `escalating/top`
- `will_breach_critical` is True only when forecast crosses 85

---

### Module 3: Graph-based Threat Correlation

```bash
# After traffic has flowed:

# Graph stats
curl http://127.0.0.1:8000/api/graph/stats

# Shortest path between attacker and asset
curl "http://127.0.0.1:8000/api/graph/path?source=45.33.32.156&target=asset:web-server-01"

# Blast radius of an IP (what's at risk if it's compromised?)
curl http://127.0.0.1:8000/api/graph/blast-radius/45.33.32.156?hops=2

# Campaign clusters (coordinated attack groups)
curl http://127.0.0.1:8000/api/graph/campaigns?min_size=2

# Pivot points (high centrality nodes)
curl http://127.0.0.1:8000/api/graph/centrality?top_n=10

# IPs related to a known IOC
curl http://127.0.0.1:8000/api/graph/related-ioc/185.220.101.1
```

**What to verify:**
- `total_nodes` and `total_edges` grow as events arrive
- `nodes_by_type` shows counts for ip, asset, ioc, mitre_technique, case
- Blast radius includes assets from your asset inventory
- Campaigns appear when multiple IPs share an asset or IOC

---

### Module 4: Explainable AI

```bash
# Full XAI report for an IP
curl http://127.0.0.1:8000/api/xai/explain/45.33.32.156

# Counterfactual only
curl http://127.0.0.1:8000/api/xai/counterfactual/45.33.32.156

# All tiers counterfactual
curl "http://127.0.0.1:8000/api/xai/counterfactual/45.33.32.156?all_tiers=true"

# Global feature importance (run after traffic accumulates)
curl http://127.0.0.1:8000/api/xai/feature-importance
```

**What to verify:**
- `counterfactual.feasible = true` means there IS a single-component change
  that would lower the severity tier
- `confidence.label` is LOW for IPs with < 2 events in history
- `feature_importance` ranks components by how often they drive verdicts
- `sample_size` grows as traffic flows through the system

---

## 5. Interpreting the Metrics for the IEEE Paper

### Key numbers to extract and report

From your evaluation JSON output, the table to include in your paper:

| Metric | Your Value | Notes |
|--------|------------|-------|
| Accuracy | X.XXX | Overall correct classifications |
| Precision | X.XXX | Alert reliability (low FP rate) |
| Recall | X.XXX | Attack detection rate |
| F1 Score | X.XXX | Harmonic mean — primary headline metric |
| AUC | X.XXX | > 0.90 = strong detector |
| FPR | X.XXX | False alarm rate (lower is better) |
| Detection Rate | X.XXX | = Recall |
| Mean Latency | X.X ms | Per-event processing time |
| Throughput | XXXX eps | Events per second |
| Peak Memory | XXX MB | RAM at peak load |
| CPU Usage | XX% | Average during evaluation |

### Recommended comparison structure for the paper

Run evaluation at 3 thresholds (20, 35, 50) on 2 datasets (CICIDS2017, NSL-KDD)
to produce a 3x2 comparison table showing precision/recall tradeoff.

### ROC curve plot (Python)

```python
import json
import matplotlib.pyplot as plt

with open("results/cicids2017_eval.json") as f:
    data = json.load(f)

fpr = data["roc"]["fpr"]
tpr = data["roc"]["tpr"]
auc = data["classification"]["auc"]

plt.figure(figsize=(6,5))
plt.plot(fpr, tpr, label=f"AHRAS (AUC={auc:.3f})")
plt.plot([0,1],[0,1],"k--", label="Random")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate (Detection Rate)")
plt.title("AHRAS ROC Curve — CICIDS2017")
plt.legend()
plt.savefig("roc_curve.pdf", bbox_inches="tight")
```

---

## 6. Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `ModuleNotFoundError: networkx` | graph module dep missing | `pip install networkx>=3.0` |
| `ModuleNotFoundError: sklearn` | evaluation dep missing | `pip install scikit-learn>=1.3` |
| `INSUFFICIENT_DATA` in forecast | IP has < 3 events in history | Let app run longer or lower min_events |
| Dataset eval: all scores = 0 | Private IP in dataset | Dataset fine — private IPs are trusted and score 0 by design |
| Graph: `available = false` | networkx import failed | Check `pip install networkx` succeeded |
| `passlib bcrypt (trapped)` at startup | passlib/bcrypt version mismatch | Harmless warning — auth still works via the bcrypt shim |
