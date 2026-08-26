"""AHRAS — ML Anomaly Model Trainer (Phase 5a)"""
import os, sys, logging, numpy as np, joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from feature_engineering import FEATURE_NAMES, cicids_row_to_raw_features, raw_features_to_vector
from config import config
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ahras.train")

def _normal(n):
    """Synthetic normal-traffic fallback. NOT representative of real network
    feature distributions -- see _real_benign() below. Kept only as a
    last-resort fallback for environments with no labeled baseline CSV
    available (e.g. a fresh checkout with no dataset mounted yet)."""
    rng = np.random.default_rng(42)
    d = {
        "packet_count":       rng.integers(1,50,n).astype(float)/500,
        "byte_count":         rng.integers(64,50000,n).astype(float)/750000,
        "unique_ports":       rng.integers(1,5,n).astype(float)/65535,
        "avg_packet_size":    rng.uniform(100,1000,n)/1500,
        "max_packet_size":    rng.uniform(200,1500,n)/1500,
        "min_packet_size":    rng.uniform(60,300,n)/1500,
        "packets_per_second": rng.uniform(0.1,50,n)/1000,
        "bytes_per_second":   rng.uniform(100,100000,n)/1500000,
        "duration":           rng.uniform(0.1,60,n)/300,
    }
    pr = rng.choice([0,1,2],n,p=[0.7,0.2,0.1])
    d["protocol_tcp"]=(pr==0).astype(float); d["protocol_udp"]=(pr==1).astype(float); d["protocol_icmp"]=(pr==2).astype(float)
    d["src_port_norm"]=rng.integers(1024,65535,n).astype(float)/65535
    d["dst_port_norm"]=rng.choice([80,443,53,22,8080],n).astype(float)/65535
    d["syn_flag_ratio"]=rng.uniform(0,0.3,n)
    d["has_high_dst_port"]=rng.choice([0.,1.],n,p=[0.7,0.3])
    d["is_known_service_port"]=rng.choice([0.,1.],n,p=[0.3,0.7])
    return np.column_stack([d[f] for f in FEATURE_NAMES])


def _real_benign(csv_path, limit=None):
    """Build the IsolationForest baseline from real labeled-benign flows,
    run through the SAME cicids_row_to_raw_features -> raw_features_to_vector
    path used at eval/runtime (feature_engineering/feature_extractor.py).
    This closes the train/inference distribution gap that caused the
    anomaly_score saturation bug: a model fit on synthetic random features
    has a decision_function spread that has no relationship to real traffic,
    so ANY calibration of that spread (fixed window or percentile-based)
    fails once real flows are scored against it.

    csv_path: a CICIDS2017/2018-style CSV (e.g. Bot.csv) with a Label column.
    Only rows whose Label is a benign token are used -- this must stay
    label-blind at inference time; it's a training-time-only baseline build.
    """
    from evaluation.dataset_loader import DatasetLoader

    loader = DatasetLoader(csv_path)
    rows = []
    for rec in loader.iter_records(limit=limit):
        if rec.label != 0:
            continue
        try:
            raw = cicids_row_to_raw_features(rec.raw_row)
            rows.append(raw_features_to_vector(raw))
        except (ValueError, KeyError):
            continue  # malformed / zero-packet row -- skip, don't fabricate

    if len(rows) < 50:
        raise ValueError(
            f"Only {len(rows)} usable benign rows found in {csv_path} -- "
            "too few to fit a baseline. Check the Label column / path."
        )
    logger.info("Loaded %d real benign flows from %s for baseline training", len(rows), csv_path)
    return np.stack(rows)


def train(output_path=None, n_samples=None, baseline_csv=None):
    output_path = output_path or config.MODEL_PATH
    baseline_csv = baseline_csv or config.TRAIN_BASELINE_CSV

    if baseline_csv:
        X = _real_benign(baseline_csv, limit=n_samples)
    else:
        logger.warning(
            "No TRAIN_BASELINE_CSV configured -- falling back to SYNTHETIC "
            "training data. Calibration built from this baseline will NOT "
            "generalize to real traffic. Set TRAIN_BASELINE_CSV (or pass "
            "baseline_csv=) to a labeled benign CSV before evaluating "
            "against real datasets."
        )
        n = n_samples or config.TRAIN_SAMPLES
        X = _normal(n)

    pipe = Pipeline([("scaler",StandardScaler()),
                     ("model",IsolationForest(n_estimators=200,contamination=config.CONTAMINATION,random_state=42,n_jobs=-1))])
    pipe.fit(X)

    # -------------------------------------------------------------------
    # Calibration: stretch decision_function()'s observed spread on the
    # TRAINING baseline to [0, 1] instead of assuming a fixed window.
    #
    # v1 of this fix (25-08-26) calibrated to the 1st/99th percentile of a
    # SYNTHETIC baseline (_normal()). That baseline's decision_function
    # spread (~-0.14 to +0.04) has no relationship to real network traffic,
    # so real evaluation flows fell almost entirely outside [score_lo,
    # score_hi] and saturated anomaly_score to ~1.0 for benign and attack
    # flows alike -- see bot_t5/t10/t15/t20 eval reports (25-08-26): FPR
    # pinned near 100% at every threshold, AUC down from 0.80 to ~0.71.
    #
    # v2 (this version): X is now real labeled-benign flows (_real_benign),
    # so the percentile window reflects an actual traffic distribution.
    # 1st/99th is padded by 5% of the span on each side as a safety margin,
    # so benign variance not present in this specific CSV doesn't clip to
    # the rails the same way the synthetic-baseline bug did.
    # -------------------------------------------------------------------
    train_scores = pipe.decision_function(X)
    score_lo, score_hi = (float(v) for v in np.percentile(train_scores, [1, 99]))
    if score_hi <= score_lo:
        # Degenerate/constant scores -- fall back to a tiny epsilon window
        # around the single observed value so normalisation never divides
        # by zero (everything will normalise to ~0.5, which is honest: the
        # model has no discriminative signal in this case).
        score_hi = score_lo + 1e-6
    else:
        pad = 0.05 * (score_hi - score_lo)
        score_lo -= pad
        score_hi += pad

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    joblib.dump({"pipeline": pipe, "score_lo": score_lo, "score_hi": score_hi}, output_path)
    logger.info(
        f"Model saved → {output_path} (calibration: score_lo={score_lo:.4f}, score_hi={score_hi:.4f})"
    )
    return pipe

if __name__ == "__main__": train()