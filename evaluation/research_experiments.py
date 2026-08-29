"""
AHRAS v5 -- Research Experiments
=================================
Answers the outstanding research-validation TODOs from the v5
architecture review:

  1. Ablation study        -- signature-only / ML-only / signature+ML /
                               +adaptive weights / +historical context /
                               full pipeline, on the SAME held-out data.
  2. Adaptive learning      -- does AdaptiveWeightLearner beat the fixed
                               hand-tuned weights on a genuinely held-out
                               split (train on one half, evaluate on the
                               other -- no leakage)?
  3. Correlation            -- does CorrelationEngine's multi-stage
                               incident confirmation reduce false positives
                               relative to raw per-event alerting?
  4. Historical risk        -- before/after: does the recidivism boost
                               improve detection of REPEAT offenders
                               specifically, without inflating overall FPR?
  5. Forecasting            -- one-step-ahead MAE/RMSE of AttackPredictor's
                               Holt's-method forecasts, and threshold-
                               crossing lead time: how many events in
                               advance does will_breach_critical actually
                               warn before a source's real risk score goes
                               CRITICAL (vs. a stable-traffic control that
                               should trigger no such warnings)?

All five reuse the existing synthetic-dataset generator + DatasetLoader +
MetricsCalculator pipeline (evaluation/generate_synthetic_dataset.py,
evaluation/dataset_loader.py, evaluation/metrics.py) so results are
apples-to-apples with the rest of the evaluation suite and don't need any
external dataset.

Usage:
    python -m evaluation.research_experiments --all
    python -m evaluation.research_experiments --ablation
    python -m evaluation.research_experiments --adaptive
    python -m evaluation.research_experiments --correlation
    python -m evaluation.research_experiments --historical
    python -m evaluation.research_experiments --forecasting

Writes evaluation/results/research_experiments_report.json and prints a
human-readable summary of every table to stdout.
"""
import argparse
import json
import logging
import math
import os
import random
import sys
import time
from typing import Dict, List, Tuple

logger = logging.getLogger("ahras.evaluation.research_experiments")
logging.basicConfig(level=logging.INFO, format="%(message)s")
# Quiet the per-sample training log lines from AdaptiveWeightLearner and the
# per-event ingest chatter from other engines -- this script prints its own
# clean tables, and thousands of "Weight update #N..." lines just bury them.
for _noisy in ("ahras.adaptive_learning", "ahras.correlation", "ahras.risk"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(HERE, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────

def _ensure_synthetic_dataset(n_total=6000, attack_frac=0.30, noise_frac=0.04):
    import csv
    from evaluation.generate_synthetic_dataset import make_dataset, OUTPUT_PATH, OUTPUT_DIR, HEADER
    # make_dataset() only builds rows in memory -- writing to disk is done
    # by generate_synthetic_dataset.py's own __main__ block, which this
    # module doesn't trigger by importing. Do that write here so every
    # experiment gets a fresh, reproducible CSV (random.seed(42) in that
    # module makes generation itself deterministic across runs).
    rows = make_dataset(n_total=n_total, attack_frac=attack_frac, noise_frac=noise_frac)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(OUTPUT_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=HEADER)
        writer.writeheader()
        writer.writerows(rows)
    return OUTPUT_PATH


def _load_records(limit=None):
    from evaluation.dataset_loader import DatasetLoader
    # Generate a dataset at least as large as what's being requested --
    # otherwise a bigger --limit silently gets truncated back down to the
    # default 6000-row dataset, making "more data" runs look identical to
    # smaller ones instead of actually using more evidence.
    n_total = max(6000, int(limit * 1.15)) if limit else 6000
    path = _ensure_synthetic_dataset(n_total=n_total)
    loader = DatasetLoader(path, dataset_type="cicids2017")
    return list(loader.iter_records(limit=limit))


def _detections_for_records(records) -> List[dict]:
    """
    Run every record through the REAL detection path -- DatasetRecord ->
    FlowRecord -> HybridDetectionEngine.analyse() (SignatureEngine + trained
    IsolationForest) -> DetectionResult -> risk-engine input dict -- and
    return the resulting dicts as a fixed snapshot.

    This replaces the old _det_from_record()/_feature_to_detection(), which
    read attack_type off record.attack_category (ground truth) instead of
    letting the model predict it -- the leakage path identified in review.
    Precomputing the whole list once (one HybridDetectionEngine instance,
    single pass) also means every RiskEngine variant/weight-config compared
    downstream sees byte-for-byte IDENTICAL detections, so any metric
    difference between variants is attributable only to the risk engine,
    never to re-running detection with different internal state.
    """
    from evaluation.runner import _record_to_flow, _detection_to_risk_input
    from detection.hybrid_detection import HybridDetectionEngine
    detector = HybridDetectionEngine()
    dets = []
    for rec in records:
        flow = _record_to_flow(rec)
        det_result = detector.analyse(flow)
        dets.append(_detection_to_risk_input(rec, det_result))
    return dets


def _new_engine():
    from risk_engine.risk_scorer import RiskEngine
    return RiskEngine(skip_dns=True)


def _metrics(y_true, y_score, latencies=None, threshold=20.0, name="variant", cats=None):
    from evaluation.metrics import MetricsCalculator
    latencies = latencies or [0.0] * len(y_true)
    calc = MetricsCalculator()
    report = calc.compute(y_true, y_score, latencies, dataset_name=name,
                           threshold=threshold, attack_categories=cats)
    return report


def _report_row(report) -> dict:
    d = report.to_dict()
    cls = d.get("classification", {})
    cm = d.get("confusion_matrix", {})
    return {
        "accuracy": round(cls.get("accuracy", 0.0), 4),
        "precision": round(cls.get("precision", 0.0), 4),
        "recall": round(cls.get("recall", 0.0), 4),
        "f1": round(cls.get("f1", 0.0), 4),
        "fpr": round(cls.get("false_positive_rate", 0.0), 4),
        "auc": round(cls.get("auc", 0.0), 4) if cls.get("auc") is not None else None,
        "tp": cm.get("TP"), "fp": cm.get("FP"), "tn": cm.get("TN"), "fn": cm.get("FN"),
    }


def _print_table(title: str, rows: Dict[str, dict]):
    print(f"\n=== {title} ===")
    cols = ["accuracy", "precision", "recall", "f1", "fpr"]
    header = f"{'variant':32s} " + " ".join(f"{c:>10s}" for c in cols)
    print(header)
    print("-" * len(header))
    for name, r in rows.items():
        print(f"{name:32s} " + " ".join(f"{r.get(c, 0.0):10.3f}" for c in cols))


# ─────────────────────────────────────────────────────────────────────────
# 1) Ablation study
# ─────────────────────────────────────────────────────────────────────────

def run_ablation_study(limit=15000, threshold=20.0) -> dict:
    """
    Single forward pass over the synthetic dataset with the FULL v5 engine
    (skip_dns=True, no adaptive learner, no asset manager). For every
    record we keep RiskEngine's own raw_components (recorded verbatim --
    see risk_scorer.py's module docstring) and reconstruct each ablation
    variant's score POST-HOC and CAUSALLY from those exact numbers --
    no re-running detection, no leakage from future rows.

    Variants (cumulative):
      signature_only        : just the signature term, scaled to 0-100
      ml_only                : just the ML anomaly flag, scaled to 0-100
      signature_plus_ml      : signature + anomaly only (density/drift/rate off)
      full_multisignal       : all four weighted base signals, no boosts
                                (== raw_components['base_risk'])
      + rule/mitre/asset boosts, trust discount (== risk_after_trust + mitre + asset)
      + historical context    : adds the causal recidivism boost RiskEngine
                                already folds in (== full pipeline, since v5
                                integrates history_boost natively)
    A separate learned-weights variant is added by run_adaptive_learning_experiment
    on a proper held-out split (mixing it in here would leak).
    """
    records = _load_records(limit=limit)
    dets = _detections_for_records(records)
    eng = _new_engine()

    y_true, cats = [], []
    sig_only, ml_only, sig_ml, full_multisignal = [], [], [], []
    with_boosts_no_history, full_pipeline = [], []
    latencies = []

    for rec, det in zip(records, dets):
        t0 = time.perf_counter()
        r = eng.evaluate(det)
        latencies.append((time.perf_counter() - t0) * 1000.0)

        rc = r.raw_components or {}
        weights = rc.get("weights_used", {"signature": 0.40, "anomaly": 0.30, "density": 0.20, "drift_rate": 0.10})
        alpha, beta = weights.get("signature", 0.40), weights.get("anomaly", 0.30)
        S = rc.get("signature", 0.0)
        A = rc.get("anomaly", 0.0)
        base_risk = rc.get("base_risk", 0.0)
        risk_after_trust = rc.get("risk_after_trust", base_risk)
        mitre_boost = rc.get("mitre_boost", 0.0)
        asset_boost = rc.get("asset_boost", 0.0)
        history_boost = rc.get("history_boost", 0.0)

        y_true.append(rec.label)
        cats.append(rec.attack_category)

        sig_only.append(max(0.0, min(100.0, S * 100.0)))
        ml_only.append(max(0.0, min(100.0, A * 100.0)))
        norm = (alpha + beta) or 1.0
        sig_ml.append(max(0.0, min(100.0, (alpha * S + beta * A) / norm * 100.0)))
        full_multisignal.append(max(0.0, min(100.0, base_risk)))
        with_boosts_no_history.append(max(0.0, min(100.0, risk_after_trust + mitre_boost + asset_boost)))
        full_pipeline.append(r.risk_score_100)

    variants = {
        "1_signature_only":             sig_only,
        "2_ml_anomaly_only":            ml_only,
        "3_signature_plus_ml":          sig_ml,
        "4_full_multisignal_fusion":    full_multisignal,
        "5_plus_rule_mitre_asset_trust": with_boosts_no_history,
        "6_full_pipeline_plus_history": full_pipeline,
    }

    rows = {}
    for name, scores in variants.items():
        report = _metrics(y_true, scores, latencies, threshold=threshold, name=name, cats=cats)
        rows[name] = _report_row(report)

    _print_table("Ablation Study (single pass, causal, threshold=%.0f)" % threshold, rows)
    return {"threshold": threshold, "n_records": len(records), "rows": rows}


# ─────────────────────────────────────────────────────────────────────────
# 2) Adaptive learning experiment
# ─────────────────────────────────────────────────────────────────────────

def run_adaptive_learning_experiment(limit=20000, threshold=20.0, train_frac=0.5) -> dict:
    """
    Fair before/after comparison, NOT the same pass used for the ablation
    table above (that would leak train->test).

      1. Split records into TRAIN (first train_frac) and TEST (remainder).
      2. Run the fixed-weight engine over TRAIN, feeding each record's
         ground-truth label to AdaptiveWeightLearner.record_feedback() as
         if it were confirmed analyst feedback (label=1 -> confirmed
         attack, label=0 -> confirmed false positive). This is exactly
         the feedback loop main.py wires in production
         (analysis worker -> adaptive_learner.record_feedback).
      3. Compare TWO fresh passes over the held-out TEST set:
           "fixed_weights"    -- RiskEngine with default ALPHA/BETA/GAMMA/DELTA
           "adaptive_weights" -- RiskEngine with the learner trained in
                                  step 2 injected via set_adaptive_learner()
         Both passes use IDENTICAL detections (same TEST records), so any
         metric difference is attributable to the weight change alone.
    """
    from adaptive_learning.weight_learner import AdaptiveWeightLearner, FeedbackSample

    records = _load_records(limit=limit)
    split = int(len(records) * train_frac)
    train_recs, test_recs = records[:split], records[split:]

    # Precompute detections ONCE per split (real HybridDetectionEngine pass,
    # no ground-truth attack_category involved) so training feedback and
    # both TEST passes below all see identical, model-derived detections.
    train_dets = _detections_for_records(train_recs)
    test_dets = _detections_for_records(test_recs)

    # -- Step 2: train the learner on TRAIN using ground-truth-as-feedback --
    learner = AdaptiveWeightLearner()
    train_engine = _new_engine()
    for rec, det in zip(train_recs, train_dets):
        r = train_engine.evaluate(det)
        rc = r.raw_components or {}
        components = {
            "signature": rc.get("signature", 0.0),
            "anomaly": rc.get("anomaly", 0.0),
            "density": rc.get("density", 0.0),
            "drift_rate": min(1.0, rc.get("drift_rate", 0.0) / 2.0),
        }
        learner.record_feedback(FeedbackSample(
            src_ip=rec.src_ip, label=rec.label, components=components,
            predicted_risk=rc.get("base_risk", 0.0),
        ))

    learned_weights = learner.get_weights()

    # -- Step 3: two clean passes over TEST, same detections, weights differ --
    def _pass(engine):
        y_true, y_score, cats, latencies = [], [], [], []
        for rec, det in zip(test_recs, test_dets):
            t0 = time.perf_counter()
            r = engine.evaluate(det)
            latencies.append((time.perf_counter() - t0) * 1000.0)
            y_true.append(rec.label)
            y_score.append(r.risk_score_100)
            cats.append(rec.attack_category)
        return y_true, y_score, cats, latencies

    fixed_engine = _new_engine()
    y_true, fixed_scores, cats, lat1 = _pass(fixed_engine)

    adaptive_engine = _new_engine()
    adaptive_engine.set_adaptive_learner(learner)
    _, adaptive_scores, _, lat2 = _pass(adaptive_engine)

    rows = {
        "fixed_weights (alpha/beta/gamma/delta = .40/.30/.20/.10)":
            _report_row(_metrics(y_true, fixed_scores, lat1, threshold, "fixed", cats)),
        "adaptive_weights (learned on train split)":
            _report_row(_metrics(y_true, adaptive_scores, lat2, threshold, "adaptive", cats)),
    }
    _print_table("Adaptive Learning: fixed vs learned weights (held-out test split)", rows)
    print(f"learned weights: {json.dumps({k: round(v, 3) for k, v in learned_weights.items()})}")

    return {
        "threshold": threshold, "train_size": len(train_recs), "test_size": len(test_recs),
        "learned_weights": {k: round(v, 4) for k, v in learned_weights.items()},
        "default_weights": {"signature": 0.40, "anomaly": 0.30, "density": 0.20, "drift_rate": 0.10},
        "rows": rows,
    }


# ─────────────────────────────────────────────────────────────────────────
# 3) Correlation false-positive-reduction experiment
# ─────────────────────────────────────────────────────────────────────────

def run_correlation_experiment(n_campaigns=60, n_noise_ips=1000, threshold=20.0) -> dict:
    """
    Synthetic multi-stage scenario, since CorrelationEngine reasons about
    INCIDENT CHAINS (a real signal only CorrelationEngine can exploit), not
    single-flow features -- so this uses hand-built event sequences rather
    than the CICIDS-style per-flow dataset used elsewhere:

      * n_campaigns genuine attacker IPs each fire a real multi-stage chain
        (Port Scan -> SSH Brute Force -> lateral Remote-Services access)
        within the correlation window -- true positives that SHOULD raise
        an incident.
      * n_noise_ips benign IPs each fire exactly ONE isolated high-signal
        event (e.g. a single SYN-flood-shaped burst from a misconfigured
        client) -- realistic single-event false-positive noise that a
        per-event threshold alone cannot distinguish from a genuine
        early-stage attack, but a correlation engine can (no follow-up
        stages ever arrive for these IPs).

    Two detection strategies over the SAME event stream:
      "raw_per_event"        : alert once per event whose risk_score_100 >= threshold
      "correlation_confirmed": alert only when CorrelationEngine.ingest()
                                actually confirms a chained incident for
                                that src_ip
    Reports total alerts / true positives / false positives / precision
    for both, so the FP-reduction from requiring correlation is explicit.
    """
    from correlation.engine import CorrelationEngine
    eng = _new_engine()
    corr = CorrelationEngine()
    random.seed(7)

    def _rand_ip():
        return f"198.51.{random.randint(0,255)}.{random.randint(1,254)}"

    # Attack-type vocabulary must match CORRELATION_RULES' required_events
    # exactly (see correlation/engine.py) for a chain to actually fire.
    # COR-005 "Full Kill Chain": Port Scan -> SSH Bruteforce -> Anomalous Behaviour.
    events = []  # (det_dict, is_genuine_attacker)
    for _ in range(n_campaigns):
        ip = _rand_ip()
        events.append(({"src_ip": ip, "attack_type": "Port Scan", "confidence": 0.7,
                         "packet_count": 200, "unique_ports": 35, "syn_count": 10,
                         "pps": 50, "anomaly_flag": True}, True))
        events.append(({"src_ip": ip, "attack_type": "SSH Bruteforce", "confidence": 0.85,
                         "packet_count": 300, "unique_ports": 5, "syn_count": 60,
                         "pps": 80, "anomaly_flag": True}, True))
        events.append(({"src_ip": ip, "attack_type": "Anomalous Behaviour", "confidence": 0.9,
                         "packet_count": 500, "unique_ports": 8, "syn_count": 20,
                         "pps": 100, "anomaly_flag": True}, True))

    for _ in range(n_noise_ips):
        ip = _rand_ip()
        events.append(({"src_ip": ip, "attack_type": "Anomalous Behaviour", "confidence": 0.55,
                         "packet_count": 60, "unique_ports": 12, "syn_count": 5,
                         "pps": 30, "anomaly_flag": True}, False))

    random.shuffle(events)

    raw_alerts_tp = raw_alerts_fp = 0
    corr_alerts_tp = corr_alerts_fp = 0
    confirmed_ips = set()

    for det, is_genuine in events:
        r = eng.evaluate(det)
        if r.risk_score_100 >= threshold:
            if is_genuine:
                raw_alerts_tp += 1
            else:
                raw_alerts_fp += 1

        corr_event = dict(det)
        corr_event["risk_score"] = r.risk_score_100
        incident = corr.ingest(corr_event)

        if incident and det["src_ip"] not in confirmed_ips:
            confirmed_ips.add(det["src_ip"])
            if is_genuine:
                corr_alerts_tp += 1
            else:
                corr_alerts_fp += 1

    def _stats(tp, fp):
        total = tp + fp
        precision = tp / total if total else 0.0
        return {"alerts": total, "true_positives": tp, "false_positives": fp,
                "precision": round(precision, 4)}

    raw_stats = _stats(raw_alerts_tp, raw_alerts_fp)
    corr_stats = _stats(corr_alerts_tp, corr_alerts_fp)
    fp_reduction_pct = (round((1 - corr_stats["false_positives"] / raw_stats["false_positives"]) * 100, 1)
                        if raw_stats["false_positives"] else 0.0)

    print("\n=== Correlation: raw per-event alerting vs correlation-confirmed incidents ===")
    print(f"raw_per_event        : {raw_stats}")
    print(f"correlation_confirmed: {corr_stats}")
    print(f"false-positive reduction: {fp_reduction_pct}%")

    return {
        "n_campaigns": n_campaigns, "n_noise_ips": n_noise_ips, "threshold": threshold,
        "raw_per_event": raw_stats, "correlation_confirmed": corr_stats,
        "false_positive_reduction_pct": fp_reduction_pct,
    }


# ─────────────────────────────────────────────────────────────────────────
# 4) Historical-risk before/after experiment
# ─────────────────────────────────────────────────────────────────────────

def run_historical_risk_experiment(n_repeat_offenders=40, n_one_off=600,
                                    visits_per_offender=6, threshold_high=50.0) -> dict:
    """
    Before/after comparison, isolating ONLY the history_boost term.

      * n_repeat_offenders IPs each generate `visits_per_offender` separate
        MEDIUM-confidence attack sessions over time (a real recidivism
        pattern -- e.g. repeated low-and-slow scan attempts that individually
        wouldn't clear the HIGH bar).
      * n_one_off IPs each generate exactly one such session (no repeat
        history to accumulate).

    A single forward pass (causal, no lookahead) computes each event's
    real risk_score_100 (WITH history_boost, exactly as production does)
    and, from the same raw_components, the score it WOULD have gotten
    WITHOUT the boost (pre_cap_risk - history_boost, reclamped). Comparing
    recall @ threshold_high (the HIGH-severity bar) between these two
    causally-identical score series isolates history's effect on repeat
    offenders specifically, while confirming it doesn't inflate the
    one-off (no-history) population's false-positive rate.
    """
    eng = _new_engine()
    random.seed(11)

    def _rand_ip(pool_tag):
        # Wide, PUBLIC address space per pool (255*254 combinations, and
        # NOT in an RFC-1918 private range -- risk_scorer._is_private()
        # would otherwise treat these as trusted local traffic and
        # short-circuit/heavily-discount the score) so that n_one_off
        # draws don't collide with each other and silently turn "one-off"
        # control IPs into accidental repeat offenders.
        return f"198.{51 + pool_tag}.{random.randint(0,255)}.{random.randint(1,254)}"

    # Deliberately weak per-event signal (base ~25/100, MEDIUM) so that
    # WITHOUT history a repeat offender never crosses the HIGH bar on
    # signal strength alone -- isolating what the recidivism boost adds.
    weak_attack = {"attack_type": "Port Scan", "confidence": 0.60,
                    "packet_count": 80, "unique_ports": 6, "syn_count": 5,
                    "pps": 15, "anomaly_flag": False}

    events = []  # (det, label, is_repeat_offender)
    for i in range(n_repeat_offenders):
        ip = _rand_ip(2)
        for _ in range(visits_per_offender):
            events.append((dict(weak_attack, src_ip=ip), 1, True))
    for i in range(n_one_off):
        ip = _rand_ip(3)
        events.append((dict(weak_attack, src_ip=ip), 1, False))
    # benign traffic for FPR context
    for i in range(n_one_off):
        ip = _rand_ip(4)
        events.append(({"src_ip": ip, "attack_type": "Normal", "confidence": 0.1,
                         "packet_count": 20, "unique_ports": 2, "syn_count": 0,
                         "pps": 2, "anomaly_flag": False}, 0, False))

    random.shuffle(events)

    # Causal recidivism counter: grows with every PRIOR event seen for this
    # IP in this run (mirrors historical_risk.engine's alert_boost/
    # incident_boost growing with alert_count/incident_count), capped at
    # 45 to match RiskEngine's own history_boost clamp. Purely a function
    # of this run's own past -- no lookahead, no ground-truth leakage.
    prior_visit_count: Dict[str, int] = {}

    y_true, with_history, without_history, is_repeat_flags, latencies = [], [], [], [], []

    for det, label, is_repeat in events:
        ip = det["src_ip"]
        count = prior_visit_count.get(ip, 0)
        history_boost = min(45.0, count * 12.0) if det["attack_type"] != "Normal" else 0.0
        det = dict(det, history_boost=history_boost)

        t0 = time.perf_counter()
        r = eng.evaluate(det)
        latencies.append((time.perf_counter() - t0) * 1000.0)

        rc = r.raw_components or {}
        pre_cap = rc.get("pre_cap_risk", r.risk_score_100)
        without = max(0.0, min(100.0, pre_cap - rc.get("history_boost", 0.0)))

        y_true.append(label)
        with_history.append(r.risk_score_100)
        without_history.append(without)
        is_repeat_flags.append(is_repeat)

        prior_visit_count[ip] = count + 1

    # Overall metrics (both variants)
    overall_with = _report_row(_metrics(y_true, with_history, latencies, 20.0, "with_history"))
    overall_without = _report_row(_metrics(y_true, without_history, latencies, 20.0, "without_history"))

    # Repeat-offender-only recall @ HIGH bar (the effect we actually care about)
    def _repeat_recall(scores):
        idx = [i for i, (t, rep) in enumerate(zip(y_true, is_repeat_flags)) if t == 1 and rep]
        if not idx:
            return 0.0
        hits = sum(1 for i in idx if scores[i] >= threshold_high)
        return round(hits / len(idx), 4)

    # One-off (no-history) population FPR-relevant recall, to confirm no
    # unwarranted inflation for IPs with nothing to build history from.
    def _oneoff_high_rate(scores):
        idx = [i for i, (t, rep) in enumerate(zip(y_true, is_repeat_flags)) if t == 1 and not rep]
        if not idx:
            return 0.0
        hits = sum(1 for i in idx if scores[i] >= threshold_high)
        return round(hits / len(idx), 4)

    rows = {
        "overall (threshold=20)": {"with_history": overall_with, "without_history": overall_without},
    }
    repeat_recall_with = _repeat_recall(with_history)
    repeat_recall_without = _repeat_recall(without_history)
    oneoff_with = _oneoff_high_rate(with_history)
    oneoff_without = _oneoff_high_rate(without_history)

    print("\n=== Historical Risk: before/after (recidivism boost) ===")
    print(f"overall with_history    : {overall_with}")
    print(f"overall without_history : {overall_without}")
    print(f"repeat-offender recall @ HIGH(>={threshold_high:.0f}) -- with_history:    {repeat_recall_with}")
    print(f"repeat-offender recall @ HIGH(>={threshold_high:.0f}) -- without_history: {repeat_recall_without}")
    print(f"one-off attacker recall @ HIGH(>={threshold_high:.0f}) -- with_history:    {oneoff_with}  (control: should barely move)")
    print(f"one-off attacker recall @ HIGH(>={threshold_high:.0f}) -- without_history: {oneoff_without}")

    return {
        "n_repeat_offenders": n_repeat_offenders, "visits_per_offender": visits_per_offender,
        "n_one_off": n_one_off, "threshold_high": threshold_high,
        "overall_with_history": overall_with, "overall_without_history": overall_without,
        "repeat_offender_recall_at_high": {"with_history": repeat_recall_with, "without_history": repeat_recall_without},
        "one_off_recall_at_high_control": {"with_history": oneoff_with, "without_history": oneoff_without},
    }


# ─────────────────────────────────────────────────────────────────────────
# 5) Forecasting accuracy (MAE/RMSE) + threshold-crossing lead time
# ─────────────────────────────────────────────────────────────────────────

def run_forecasting_experiment(n_escalating=30, n_stable=30, visits_per_ip=12,
                                critical_threshold=85.0) -> dict:
    """
    forecast.predictor.AttackPredictor makes two claims that were never
    actually measured: (a) its Holt's-method forecasts are accurate
    one-step-ahead, and (b) will_breach_critical gives analysts useful
    advance warning before a source's risk score actually goes CRITICAL.
    This experiment measures both against REAL RiskEngine output (not a
    synthetic curve), using forecast.predictor.forecast_accuracy() and
    .threshold_crossing_lead_time() -- both causal/walk-forward, see
    their docstrings for why that rules out lookahead leakage.

    Two populations, built the same causal-event-stream way as
    run_historical_risk_experiment() (fresh RiskEngine, wide public-IP
    pool, no lookahead):

      escalating -- one attacker IP whose confidence/packet-volume/
                    port-breadth genuinely ramps up over `visits_per_ip`
                    visits (recon -> active scan -> exploitation), so its
                    real risk_score_100 series should trend upward and,
                    for most instances, eventually cross CRITICAL. This
                    is the population the lead-time claim is about.
      stable     -- an IP with steady, non-escalating low-confidence
                    traffic. Used as a control: forecast MAE/RMSE should
                    still be small (nothing hard to predict about a flat
                    series), and there should be essentially NO threshold
                    crossings to warn about -- a forecaster that "warns"
                    on stable traffic would be reporting false positives
                    on its own early-warning signal.

    IMPORTANT, VERIFIED FINDING (read before tuning this scenario to
    "improve" the lead-time number): risk_scorer.py's rule_boosts and
    strength_multiplier are DISCRETE STEP FUNCTIONS by design (e.g.
    unique_ports>30, syn_count>50, and 4-5/5 signal-strength all firing
    together on the same event) -- not a smooth continuation of whatever
    trend preceded them. A smoothly, monotonically escalating attacker
    (confirmed at visit counts of 12, 20, 24, and 30, multiple random
    IPs, both steep and gentle ramps) reliably produces a near-linear
    sub-CRITICAL risk_score_100 series right up until several rule
    thresholds cross on the SAME event, at which point the score jumps
    straight to (or near) 100 in a single step. Holt's linear method has
    no way to see that cliff coming from a smoothly-growing history that
    never previously exceeded ~30/100 -- so measured threshold-crossing
    coverage against this scenario is genuinely ~0%, not a bug in either
    the forecaster or this harness. That is itself the reportable result:
    AHRAS's forecaster is accurate (see MAE/RMSE) while RiskEngine's
    score remains in its smooth regime, but the CURRENT rule-based cliff
    design is fundamentally unpredictable by a trend-following model --
    an early-warning capability against THIS engine would need either a
    smoother scoring function or a forecaster that models discrete-event
    risk (e.g. survival analysis on "how many more rule-boost-eligible
    events until this IP's counts cross a threshold"), not a Holt's-
    method fix. See the printed caveat and the `lead_time` dict's
    `coverage_note` field.
    """
    from forecast.predictor import AttackPredictor, forecast_accuracy, threshold_crossing_lead_time

    random.seed(23)
    predictor = AttackPredictor(horizon=5)

    def _rand_ip(pool_tag):
        return f"192.0.{pool_tag}.{random.randint(1, 254)}"

    def _risk_series_for_ip(ip: str, visit_dets: List[dict]) -> List[float]:
        eng = _new_engine()  # fresh engine per IP: no cross-IP state leakage
        series = []
        for det in visit_dets:
            r = eng.evaluate(dict(det, src_ip=ip))
            series.append(r.risk_score_100)
        return series

    def _escalating_visits(n):
        """Confidence, packet volume, and port/syn breadth all ramp up
        linearly over the visit sequence -- a slow recon-to-exploitation
        pattern, not a step function, so there's real signal for Holt's
        trend term to pick up on causally."""
        visits = []
        for i in range(n):
            frac = i / max(1, n - 1)
            visits.append({
                "attack_type": "Port Scan" if frac < 0.5 else "Brute Force",
                "confidence": round(0.35 + 0.6 * frac, 3),
                "packet_count": int(20 + 480 * frac),
                "unique_ports": int(3 + 45 * frac),
                "syn_count": int(2 + 110 * frac),
                "pps": round(10 + 900 * frac, 1),
                "anomaly_flag": frac > 0.3,
            })
        return visits

    def _stable_visits(n):
        visits = []
        for _ in range(n):
            visits.append({
                "attack_type": "Anomalous Behaviour", "confidence": 0.4,
                "packet_count": 25, "unique_ports": 4, "syn_count": 2,
                "pps": 12.0, "anomaly_flag": False,
            })
        return visits

    all_errors: List[float] = []
    per_ip_accuracy = []
    lead_times = []
    escalating_crossed = 0
    escalating_warned_in_time = 0

    for i in range(n_escalating):
        ip = _rand_ip(10 + i % 40)
        series = _risk_series_for_ip(ip, _escalating_visits(visits_per_ip))
        errs = forecast_accuracy(predictor, series)
        if errs["n"] > 0:
            per_ip_accuracy.append(errs)
            all_errors.append(errs)
        lead = threshold_crossing_lead_time(predictor, series, threshold=critical_threshold)
        crossed = any(v >= critical_threshold for v in series)
        if crossed:
            escalating_crossed += 1
            if lead is not None:
                escalating_warned_in_time += 1
                lead_times.append(lead)

    stable_errors = []
    stable_false_warnings = 0
    for i in range(n_stable):
        ip = _rand_ip(60 + i % 40)
        series = _risk_series_for_ip(ip, _stable_visits(visits_per_ip))
        errs = forecast_accuracy(predictor, series)
        if errs["n"] > 0:
            stable_errors.append(errs)
        if threshold_crossing_lead_time(predictor, series, threshold=critical_threshold) is not None:
            stable_false_warnings += 1

    def _pool(rows):
        total_n = sum(r["n"] for r in rows)
        if not total_n:
            return {"n": 0, "mae": 0.0, "rmse": 0.0}
        # Pool by re-weighting each IP's MAE/RMSE by its own sample count --
        # equivalent to averaging over every individual one-step error
        # without re-touching raw errors from each fresh engine's run.
        mae = sum(r["mae"] * r["n"] for r in rows) / total_n
        rmse = math.sqrt(sum((r["rmse"] ** 2) * r["n"] for r in rows) / total_n)
        return {"n": total_n, "mae": round(mae, 3), "rmse": round(rmse, 3)}

    escalating_pooled = _pool(per_ip_accuracy)
    stable_pooled = _pool(stable_errors)

    lead_time_stats = {
        "n_escalating_ips": n_escalating,
        "n_crossed_critical": escalating_crossed,
        "n_warned_before_crossing": escalating_warned_in_time,
        "warning_coverage_pct": round(100 * escalating_warned_in_time / escalating_crossed, 1) if escalating_crossed else None,
        "mean_lead_time_events": round(sum(lead_times) / len(lead_times), 2) if lead_times else None,
        "median_lead_time_events": (sorted(lead_times)[len(lead_times) // 2] if lead_times else None),
        "min_lead_time_events": min(lead_times) if lead_times else None,
        "max_lead_time_events": max(lead_times) if lead_times else None,
        "coverage_note": (
            "Low/zero coverage here reflects RiskEngine's own rule_boosts + "
            "strength_multiplier being discrete step functions (multiple "
            "behavioural thresholds firing on the same event) rather than a "
            "smooth continuation of the pre-crossing trend -- see this "
            "function's docstring. This is a property of the scored risk "
            "function, verified across ramp steepness/duration, not a "
            "forecaster or harness bug."
        ),
    }

    print("\n=== Forecasting: one-step-ahead accuracy (walk-forward, causal) ===")
    print(f"escalating population : {escalating_pooled}")
    print(f"stable (control)      : {stable_pooled}")
    print("\n=== Forecasting: threshold-crossing early-warning lead time (CRITICAL>=%.0f) ===" % critical_threshold)
    print(f"escalating IPs that reached CRITICAL : {escalating_crossed}/{n_escalating}")
    print(f"  warned in advance (>=1 event lead)  : {escalating_warned_in_time} "
          f"({lead_time_stats['warning_coverage_pct']}% coverage)")
    print(f"  mean lead time  : {lead_time_stats['mean_lead_time_events']} events")
    print(f"  median lead time: {lead_time_stats['median_lead_time_events']} events")
    print(f"stable-control false warnings (should be ~0): {stable_false_warnings}/{n_stable}")
    if escalating_warned_in_time == 0 and escalating_crossed > 0:
        print("NOTE: 0% coverage is a genuine finding, not a bug -- RiskEngine's "
              "rule-boost thresholds create a step-function jump to CRITICAL "
              "that a smooth (Holt's-method) trend forecaster cannot anticipate. "
              "See lead_time.coverage_note in the JSON output.")

    return {
        "visits_per_ip": visits_per_ip, "critical_threshold": critical_threshold,
        "accuracy": {"escalating": escalating_pooled, "stable_control": stable_pooled},
        "lead_time": lead_time_stats,
        "stable_control_false_warnings": stable_false_warnings,
        "stable_control_ips": n_stable,
    }


# ─────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="AHRAS v5 research experiments")
    p.add_argument("--all", action="store_true")
    p.add_argument("--ablation", action="store_true")
    p.add_argument("--adaptive", action="store_true")
    p.add_argument("--correlation", action="store_true")
    p.add_argument("--historical", action="store_true")
    p.add_argument("--forecasting", action="store_true")
    p.add_argument("--limit", type=int, default=15000, help="dataset rows for ablation/adaptive passes")
    args = p.parse_args()

    run_any = args.ablation or args.adaptive or args.correlation or args.historical or args.forecasting
    if not run_any:
        args.all = True

    report = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}

    if args.all or args.ablation:
        report["ablation_study"] = run_ablation_study(limit=args.limit)
    if args.all or args.adaptive:
        report["adaptive_learning"] = run_adaptive_learning_experiment(limit=max(args.limit, 20000))
    if args.all or args.correlation:
        report["correlation_fp_reduction"] = run_correlation_experiment()
    if args.all or args.historical:
        report["historical_risk_before_after"] = run_historical_risk_experiment()
    if args.all or args.forecasting:
        report["forecasting"] = run_forecasting_experiment()

    out_path = os.path.join(RESULTS_DIR, "research_experiments_report.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\nFull report written to {out_path}")


if __name__ == "__main__":
    main()
