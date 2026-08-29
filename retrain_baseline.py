"""Capture and train AHRAS anomaly baseline on real traffic."""
from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import shutil
import time

import joblib
import numpy as np

from config import config
from detection.signature_engine import SignatureEngine
from feature_engineering import FlowFeatureExtractor, Preprocessor, FEATURE_NAMES
from sensors.flow_generator import FlowGenerator
from sensors.packet_sniffer import PacketSniffer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("ahras.retrain")

BASELINE_PATH = os.path.join("data", "baseline_normal.npy")
BASELINE_META = os.path.join("data", "baseline_meta.jsonl")


def _capture(minutes: float, interface: str | None = None):
    pkt_q = queue.Queue(maxsize=20000)
    flow_q = queue.Queue(maxsize=20000)
    sniffer = PacketSniffer(pkt_q, interface=interface)
    flow_gen = FlowGenerator(pkt_q, flow_q)
    fx = FlowFeatureExtractor()
    sig = SignatureEngine()

    sniffer.start()
    flow_gen.start()
    logger.info("Capturing normal traffic for %.1f minute(s)", minutes)

    vectors, meta = [], []
    kept = dropped = 0
    deadline = time.time() + minutes * 60

    try:
        while time.time() < deadline:
            try:
                flow = flow_q.get(timeout=1.0)
            except queue.Empty:
                continue
            sig_result = sig.analyse(flow)
            if sig_result is not None and sig_result.attack_type != "Normal":
                dropped += 1
                continue
            vec = Preprocessor.clean(fx.extract(flow))
            vectors.append(vec.values.copy())
            meta.append({
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "protocol": flow.protocol,
                "dst_port": flow.dst_port,
                "packet_count": flow.packet_count,
                "pps": round(flow.packets_per_second, 3),
            })
            kept += 1
    finally:
        sniffer.stop()
        flow_gen.stop()

    if not kept:
        raise RuntimeError("No clean flows captured")

    X_new = np.asarray(vectors, dtype=np.float32)
    if os.path.exists(BASELINE_PATH):
        old = np.load(BASELINE_PATH)
        X = np.vstack([old, X_new])
    else:
        X = X_new
    np.save(BASELINE_PATH, X)

    with open(BASELINE_META, "a", encoding="utf-8") as fh:
        for item in meta:
            fh.write(json.dumps(item) + "\n")

    logger.info("Capture complete: kept=%d filtered=%d total_baseline=%d", kept, dropped, len(X))


def _train(min_flows: int = 300):
    if not os.path.exists(BASELINE_PATH):
        raise FileNotFoundError(f"No baseline at {BASELINE_PATH}; import/capture benign data first")

    X = np.asarray(np.load(BASELINE_PATH), dtype=np.float32)
    if X.ndim != 2 or X.shape[1] != len(FEATURE_NAMES):
        raise RuntimeError(f"Baseline shape {X.shape}; expected (?, {len(FEATURE_NAMES)})")
    if len(X) < min_flows:
        logger.warning("Only %d baseline rows; recommended minimum is %d", len(X), min_flows)
    if not np.all(np.isfinite(X)):
        raise RuntimeError("Baseline contains NaN/Infinity")

    from sklearn.ensemble import IsolationForest
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split

    pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("model", IsolationForest(
            n_estimators=200,
            contamination=config.CONTAMINATION,
            random_state=42,
            n_jobs=-1,
        )),
    ])

    # Calibration: MUST be saved as {"pipeline", "score_lo", "score_hi"} --
    # predict_anomaly.py's loader checks `isinstance(obj, dict) and
    # "pipeline" in obj`. A bare pipe fails that check silently, gets
    # treated as a "legacy uncalibrated model", and gets auto-retrained on
    # SYNTHETIC data the next time anything loads it -- discarding this
    # real-data training with no error. See detection/anomaly_engine/
    # train_model.py::train() for the identical calibration computation --
    # including the held-out split below, kept in sync with that function
    # (27-08-26): calibrating on the same rows the model was fit on tends
    # to read as more "confident"/wider-spread than genuinely unseen
    # traffic, so an 80/20 held-out split is used whenever there's enough
    # data for one to be meaningful.
    if len(X) >= 100:
        X_fit, X_calib = train_test_split(X, test_size=0.2, random_state=42)
    else:
        logger.warning(
            "Only %d baseline rows -- too few for a held-out calibration "
            "split; calibrating on the fitting data itself.", len(X),
        )
        X_fit, X_calib = X, X

    pipe.fit(X_fit)
    train_scores = pipe.decision_function(X_calib)
    score_lo, score_hi = (float(v) for v in np.percentile(train_scores, [1, 99]))
    if score_hi <= score_lo:
        score_hi = score_lo + 1e-6
    else:
        pad = 0.05 * (score_hi - score_lo)
        score_lo -= pad
        score_hi += pad

    out_path = config.MODEL_PATH
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    if os.path.exists(out_path):
        backup = f"{out_path}.bak-{int(time.time())}"
        shutil.copy2(out_path, backup)
        logger.info("Backed up old model to %s", backup)
    joblib.dump({"pipeline": pipe, "score_lo": score_lo, "score_hi": score_hi}, out_path)
    # Phase 6: register every successful training run as an immutable artifact.
    try:
        from mlops import ModelRegistry
        version = time.strftime("iforest-%Y%m%d-%H%M%S", time.gmtime())
        ModelRegistry(model_path=out_path).register(version, metadata={
            "algorithm": "IsolationForest", "feature_count": len(FEATURE_NAMES),
            "training_rows": int(len(X)), "contamination": float(config.CONTAMINATION),
            "calibration": {"score_lo": score_lo, "score_hi": score_hi},
        })
        logger.info("Registered model version %s", version)
    except Exception as exc:
        logger.warning("Model registry update skipped: %s", exc)
    logger.info(
        "Trained model on %d REAL baseline vectors -> %s (calibration: score_lo=%.4f, score_hi=%.4f)",
        len(X), out_path, score_lo, score_hi,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    cap = sub.add_parser("capture")
    cap.add_argument("--minutes", type=float, default=30.0)
    cap.add_argument("--interface", default=None)
    tr = sub.add_parser("train")
    tr.add_argument("--min-flows", type=int, default=300)
    args = parser.parse_args()
    if args.cmd == "capture":
        _capture(args.minutes, args.interface)
    else:
        _train(args.min_flows)