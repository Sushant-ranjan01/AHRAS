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

    pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("model", IsolationForest(
            n_estimators=200,
            contamination=config.CONTAMINATION,
            random_state=42,
            n_jobs=-1,
        )),
    ])
    pipe.fit(X)

    out_path = config.MODEL_PATH
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    if os.path.exists(out_path):
        backup = f"{out_path}.bak-{int(time.time())}"
        shutil.copy2(out_path, backup)
        logger.info("Backed up old model to %s", backup)
    joblib.dump(pipe, out_path)
    logger.info("Trained model on %d REAL baseline vectors -> %s", len(X), out_path)


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