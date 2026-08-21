"""
AHRAS — Real-Traffic Baseline Capture & Anomaly Model Retrainer
==================================================================

WHY THIS EXISTS
----------------
detection/anomaly_engine/train_model.py fits the IsolationForest on 1,000
hand-crafted SYNTHETIC "normal" flows (see _normal() in that file) — it has
never seen a single packet from your actual network. Real traffic (CDN
video, QUIC, background sync, streaming, etc.) has a different statistical
shape than that synthetic baseline, so a lot of genuinely normal traffic on
YOUR network gets scored as an outlier and shows up as "Anomalous Behaviour"
in the dashboard.

This script fixes that at the source: it captures a real baseline of your
own network's "quiet/normal" traffic, runs it through the exact same
feature-extraction pipeline the live system uses, and refits the model on
that instead of synthetic data.

HOW TO USE
----------
1. Run as Administrator (Windows) / root (Linux), same requirement as
   main.py, since this uses the same scapy-based PacketSniffer.

2. Capture a session while using your network completely normally — browse,
   stream something, take a video call, let background sync run. Don't run
   port scans / floods / anything attack-like during capture, since that
   would poison the "normal" baseline.

       python retrain_baseline.py capture --minutes 30

   Each run APPENDS to data/baseline_normal.npy, so repeat this at a few
   different times (morning, evening, a video-call session, a weekend) to
   get a baseline that actually covers the range of things your network
   normally does. More diversity here = fewer false positives later.
   A defensive filter is applied during capture: any flow the existing
   SignatureEngine already flags as an attack (port scan, flood, SSH
   brute-force, etc.) is dropped and never enters the baseline, in case
   something unexpected happens on the network mid-capture.

3. Once you've got a few sessions in (a few hundred to a few thousand
   flows), retrain:

       python retrain_baseline.py train

   This backs up the old synthetic-trained model (models/anomaly_model.pkl
   -> models/anomaly_model.pkl.bak-<timestamp>) and writes a new one fitted
   on your real captured traffic. Restart AHRAS (python main.py) afterwards
   to load it.

4. If it's still over-flagging after this, it's most likely still too
   narrow a baseline (didn't cover enough traffic variety) — capture a few
   more sessions and retrain again — or CONTAMINATION in config/settings.py
   (currently 0.05) needs lowering.
"""
import argparse
import json
import logging
import os
import queue
import sys
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import config
from detection.signature_engine import SignatureEngine
from feature_engineering import FlowFeatureExtractor, Preprocessor
from sensors.flow_generator import FlowGenerator
from sensors.packet_sniffer import PacketSniffer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("ahras.retrain")

BASELINE_PATH = os.path.join("data", "baseline_normal.npy")
BASELINE_META = os.path.join("data", "baseline_meta.jsonl")


def _capture(minutes: float, interface: str = None):
    pkt_q = queue.Queue(maxsize=20000)
    flow_q = queue.Queue(maxsize=20000)
    sniffer = PacketSniffer(pkt_q, interface=interface)
    flow_gen = FlowGenerator(pkt_q, flow_q)
    fx = FlowFeatureExtractor()
    sig = SignatureEngine()

    sniffer.start()
    flow_gen.start()
    logger.info(
        f"Capturing on interface={sniffer.interface or 'auto-detect'} for "
        f"{minutes:.1f} minute(s). Use the network normally now (browse, "
        f"stream, video call) — avoid scans/floods/anything attack-like."
    )

    vectors, meta = [], []
    kept = dropped_malicious = 0
    deadline = time.time() + minutes * 60
    last_report = time.time()

    while time.time() < deadline:
        try:
            flow = flow_q.get(timeout=1.0)
        except queue.Empty:
            flow = None

        if flow is not None:
            # Defensive filter: never let anything the SignatureEngine already
            # considers an attack (port scan, flood, SSH brute-force, DNS amp,
            # beaconing, etc.) leak into the "normal" baseline.
            sig_result = sig.analyse(flow)
            if sig_result is not None and sig_result.attack_type != "Normal":
                dropped_malicious += 1
            else:
                vec = Preprocessor.clean(fx.extract(flow))
                vectors.append(vec.values)
                meta.append({
                    "src_ip": flow.src_ip, "dst_ip": flow.dst_ip,
                    "protocol": flow.protocol, "dst_port": flow.dst_port,
                    "packet_count": flow.packet_count,
                    "pps": round(flow.packets_per_second, 1),
                })
                kept += 1

        if time.time() - last_report > 15:
            remaining = max(0, int(deadline - time.time()))
            logger.info(
                f"...{kept} clean flows captured so far "
                f"(packets seen={sniffer.captured}, filtered-as-attack={dropped_malicious}, "
                f"~{remaining}s remaining)"
            )
            last_report = time.time()

    sniffer.stop()
    flow_gen.stop()

    if kept == 0:
        logger.error(
            "No usable flows captured. Check you're running as Administrator/root, "
            "Npcap is installed (Windows), and the interface is correct — run "
            "check_capture.py to diagnose. Nothing was written to the baseline."
        )
        return

    X_new = np.array(vectors, dtype=np.float32)
    os.makedirs("data", exist_ok=True)

    if os.path.exists(BASELINE_PATH):
        X_old = np.load(BASELINE_PATH)
        X = np.vstack([X_old, X_new])
        logger.info(f"Appended {kept} new flows to existing baseline ({len(X_old)} -> {len(X)} total).")
    else:
        X = X_new
        logger.info(f"Started new baseline with {kept} flows.")

    np.save(BASELINE_PATH, X)
    with open(BASELINE_META, "a") as f:
        for m in meta:
            f.write(json.dumps(m) + "\n")

    logger.info(
        f"Session done: kept={kept}, filtered-as-attack={dropped_malicious}. "
        f"Baseline now has {len(X)} total flows -> {BASELINE_PATH}"
    )
    logger.info(
        "Capture a few more sessions at different times/activities for a more "
        "representative baseline, then run: python retrain_baseline.py train"
    )


def _train(min_flows: int = 300):
    if not os.path.exists(BASELINE_PATH):
        logger.error(f"No baseline found at {BASELINE_PATH}. Run 'capture' first.")
        return

    X = np.load(BASELINE_PATH)
    logger.info(f"Loaded baseline: {len(X)} real flows, {X.shape[1]} features each.")

    if len(X) < min_flows:
        logger.warning(
            f"Only {len(X)} flows in the baseline — recommend at least ~{min_flows} "
            f"across a few sessions/times of day before training, or the model will "
            f"still be under-representative. Proceeding since you asked, but consider "
            f"capturing more first (python retrain_baseline.py capture --minutes 30)."
        )

    from sklearn.ensemble import IsolationForest
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    import joblib

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
    if os.path.exists(out_path):
        backup = f"{out_path}.bak-{int(time.time())}"
        os.replace(out_path, backup)
        logger.info(f"Backed up old synthetic-trained model to {backup}")

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    joblib.dump(pipe, out_path)
    logger.info(f"New model trained on {len(X)} REAL flows from your own network -> {out_path}")
    logger.info("Restart AHRAS (python main.py) to load the new model.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Capture real traffic and retrain AHRAS's anomaly model on it instead of synthetic data."
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    cap = sub.add_parser("capture", help="Capture N minutes of real traffic as a 'normal' baseline")
    cap.add_argument("--minutes", type=float, default=30.0)
    cap.add_argument("--interface", type=str, default=None, help="Override auto-detected interface")

    tr = sub.add_parser("train", help="Retrain the anomaly model on all captured baseline flows")
    tr.add_argument("--min-flows", type=int, default=300)

    args = ap.parse_args()
    if args.cmd == "capture":
        _capture(args.minutes, args.interface)
    elif args.cmd == "train":
        _train(args.min_flows)
