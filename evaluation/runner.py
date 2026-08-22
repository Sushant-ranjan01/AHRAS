"""
AHRAS v4 -- Evaluation Runner
===============================
Feeds DatasetLoader records through AHRAS's HybridDetectionEngine +
RiskEngine, collects raw scores, then hands off to MetricsCalculator.

Usage (standalone script):
    python -m evaluation.runner --dataset /path/to/cicids.csv --limit 10000

Usage (programmatic):
    from evaluation import EvaluationRunner
    report = EvaluationRunner().run(dataset_path="cicids.csv", limit=5000)
    print(report.summary_line())
"""
import argparse
import json
import logging
import os
import sys
import time
from typing import Optional

import psutil

logger = logging.getLogger("ahras.evaluation.runner")


def _feature_to_detection(record) -> dict:
    """
    Map a DatasetRecord's feature dict onto the dict schema that
    HybridDetectionEngine / RiskEngine expect as input.

    AHRAS engine keys used:
      src_ip, attack_type, confidence, packet_count, pps,
      unique_ports, syn_count, anomaly_flag
    """
    f = record.features

    # Packet count: use whichever field is available
    pkt = (f.get("Total Fwd Packets", 0) + f.get("Total Backward Packets", 0)
           or f.get("spkts", 0) + f.get("dpkts", 0)
           or f.get("count", 0))

    # Bytes per second / flow rate
    bps  = f.get("Flow Bytes/s",    f.get("sload", 0) + f.get("dload", 0))
    pps  = f.get("Flow Packets/s",  f.get("rate", 0))
    syns = f.get("SYN Flag Count",  0)
    dur  = max(f.get("Flow Duration", 1) / 1e6, f.get("dur", 1), 0.001)
    # unique_ports: a genuine COUNT of distinct ports/services contacted
    # (a scan-breadth signal), NOT the destination port number itself.
    # BUG FIX: this used to fall back to the raw "Destination Port" value
    # (e.g. 443, 8080) when no count field was present, which silently
    # added a flat risk bonus to nearly all traffic since real port
    # numbers are almost always >30 -- inflating false positives on any
    # CICIDS2017-schema dataset (which has no aggregate count field at
    # single-flow granularity). Only genuine aggregate-count fields
    # (NSL-KDD's dst_host_srv_count/dst_host_count) are used; anything
    # else correctly defaults to 0 rather than a look-alike value.
    ports = f.get("dst_host_srv_count", f.get("dst_host_count", 0))

    # confidence: use packet length std as proxy (higher variance = more suspicious)
    pkt_std   = f.get("Packet Length Std", f.get("sbytes", 0))
    confidence = min(1.0, float(pkt_std) / 5000.0) if pkt_std else 0.2

    # anomaly flag: MUST be derived only from the row's own traffic features,
    # never from record.label / record.attack_category. Using the ground-truth
    # label here would hand the answer straight to the risk engine before
    # scoring, artificially inflating recall/AUC (the model would effectively
    # already know which rows are attacks). See _statistical_anomaly_flag().
    anomaly_flag = _statistical_anomaly_flag(f)

    return {
        "src_ip":       record.src_ip,
        "attack_type":  _category_to_attack_type(record.attack_category),
        "confidence":   confidence,
        "packet_count": int(pkt),
        "pps":          float(pps) if pps else float(pkt) / dur,
        "unique_ports": int(ports),
        "syn_count":    int(syns),
        "bytes_per_sec": float(bps),
        "anomaly_flag": anomaly_flag,
        # BUG FIX: pass the dataset's own row timestamp (when the loader
        # parsed one -- currently cicids2017 only) through to RiskEngine
        # instead of letting it default to wall-clock time.time(). Without
        # this, RiskEngine._rate()/_density() treat "however many rows got
        # processed in the last real-world fraction-of-a-second" as if it
        # were "packets in the last 30 real seconds", so any ordinary IP
        # that just happens to appear >20-30 times anywhere in a fast batch
        # replay gets scored as if it were bursting -- inflating false
        # positives even on datasets with ZERO actual attacks. When no
        # event_time is available (NSL-KDD, UNSW-NB15, generic CSVs have no
        # real per-row timing), this is None and RiskEngine falls back to
        # its normal wall-clock behavior, same as live traffic.
        "event_time":   getattr(record, "event_time", None),
    }


def _statistical_anomaly_flag(f: dict) -> bool:
    """
    Blind, unsupervised-style anomaly heuristic computed ONLY from a row's own
    traffic-shape features -- it never looks at record.label or
    record.attack_category. This stands in for what the live HybridDetectionEngine's
    IsolationForest (detection/anomaly_engine.py) would flag in production,
    without giving the evaluator a peek at the answer key.

    Requires >=2 independent statistical signals to agree before flagging, so
    ordinary noisy-but-benign flows don't trip it on a single loose threshold:
      - unusually high packet-length variance (bursty / crafted payloads)
      - high SYN count (scan / flood shape)
      - very low inter-arrival-time variance (scripted, machine-paced traffic)
      - one-directional flood (all forward packets, no replies)
      - extreme packet rate sustained over a real volume of packets
    """
    signals = 0

    pkt_std = f.get("Packet Length Std", 0) or f.get("sbytes", 0) or 0
    if pkt_std and float(pkt_std) > 800:
        signals += 1

    syn = f.get("SYN Flag Count", 0) or 0
    if float(syn) > 20:
        signals += 1

    iat_std = f.get("Flow IAT Std", None)
    if iat_std is not None and float(iat_std) < 50:
        signals += 1

    fwd = f.get("Total Fwd Packets", 0) or f.get("spkts", 0) or 0
    bwd = f.get("Total Backward Packets", 0) or f.get("dpkts", 0) or 0
    if float(bwd) == 0 and float(fwd) > 10:
        signals += 1

    pps = f.get("Flow Packets/s", 0) or f.get("rate", 0) or 0
    if pps and float(pps) > 1000 and (float(fwd) + float(bwd)) >= 20:
        signals += 1

    return signals >= 2


def _category_to_attack_type(category: str) -> str:
    """Map raw dataset label strings to AHRAS attack_type taxonomy."""
    cat = (category or "").lower().strip()
    if cat in ("benign", "normal", "normal.", "0", ""):
        return "Normal"
    if "dos" in cat or "ddos" in cat or "flood" in cat:
        return "Traffic Flood"
    if "portscan" in cat or "port scan" in cat or "probe" in cat:
        return "Port Scan"
    if "brute" in cat or "brute force" in cat or "ftp-patator" in cat or "ssh-patator" in cat:
        return "Brute Force"
    if "botnet" in cat or "bot" in cat:
        return "Botnet"
    if "web" in cat or "sql" in cat or "xss" in cat:
        return "Web Attack"
    if "infiltrat" in cat:
        return "Infiltration"
    if "heartbleed" in cat:
        return "Exploit"
    if "generic" in cat or "exploit" in cat:
        return "Exploit"
    if "backdoor" in cat:
        return "Backdoor"
    return "Anomalous Behaviour"


class EvaluationRunner:
    """
    Orchestrates the full evaluation pipeline:
      DatasetLoader -> detection mapping -> RiskEngine -> MetricsCalculator
    """

    def __init__(self):
        self._setup_engines()

    def _setup_engines(self):
        """Lazy import so this module can be imported without a full AHRAS
        startup (important for the pytest suite which mocks heavy modules)."""
        try:
            sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
            from risk_engine.risk_scorer import RiskEngine
            from detection.hybrid_detection import HybridDetectionEngine
            from evaluation.metrics import MetricsCalculator

            # skip_dns=True: bulk evaluation runs through thousands of unique
            # dataset IPs that almost never have real PTR records — see
            # RiskEngine._trust()'s docstring for why this is safe here but
            # must stay off for live traffic.
            self._risk_eng = RiskEngine(skip_dns=True)
            try:
                self._detector = HybridDetectionEngine()
            except Exception:
                self._detector = None   # optional — fallback to risk_eng only
            self._calc = MetricsCalculator()
            logger.info("EvaluationRunner engines ready")
        except Exception as e:
            logger.error(f"Engine init failed: {e}")
            raise

    def run(
        self,
        dataset_path: str,
        limit: Optional[int] = None,
        threshold: float = 20.0,
        dataset_name: Optional[str] = None,
        sample: bool = False,
    ):
        from evaluation.dataset_loader import DatasetLoader
        from evaluation.metrics import MetricsCalculator

        name = dataset_name or os.path.basename(dataset_path)
        loader = DatasetLoader(dataset_path)
        mode = "reservoir-sampled" if (sample and limit) else "head-truncated" if limit else "full-file"
        logger.info(f"Starting evaluation on {name} (limit={limit}, mode={mode}, threshold={threshold})")
        if limit and not sample:
            logger.warning(
                f"[{name}] limit={limit} with sample=False reads only the FIRST "
                f"{limit} rows of the file. For chronologically-ordered files "
                f"(e.g. CICIDS2017 per-day CSVs) where attacks are clustered "
                f"later in the file, this can under-represent or entirely miss "
                f"attack traffic and make precision/recall look misleadingly "
                f"bad or good. Pass --sample (CLI) / sample=True (API) for a "
                f"representative random sample across the whole file instead."
            )

        y_true, y_score, latencies, categories = [], [], [], []
        proc = psutil.Process()
        cpu_samples = []
        peak_mem_mb = 0.0

        for record in loader.iter_records(limit=limit, sample=sample):
            det_input = _feature_to_detection(record)

            t0 = time.perf_counter()
            try:
                risk = self._risk_eng.evaluate(det_input)
                score = risk.risk_score_100
            except Exception as e:
                logger.warning(f"Risk eval failed for {record.src_ip}: {e}")
                score = 0.0
            latency_ms = (time.perf_counter() - t0) * 1000

            y_true.append(record.label)
            y_score.append(score)
            latencies.append(latency_ms)
            categories.append(record.attack_category)

            # Sample CPU/memory every 100 records
            if len(y_true) % 100 == 0:
                cpu_samples.append(proc.cpu_percent(interval=None))
                mem_mb = proc.memory_info().rss / 1024 / 1024
                peak_mem_mb = max(peak_mem_mb, mem_mb)

        mean_cpu = sum(cpu_samples) / len(cpu_samples) if cpu_samples else 0.0
        calc = MetricsCalculator()
        report = calc.compute(
            y_true=y_true, y_score=y_score, latencies_ms=latencies,
            peak_memory_mb=peak_mem_mb, mean_cpu_pct=mean_cpu,
            dataset_name=name, threshold=threshold,
            attack_categories=categories,
        )
        logger.info(report.summary_line())
        return report

    def run_multiple(self, paths: list, **kwargs):
        """Run evaluation on multiple dataset files and return all reports."""
        reports = []
        for path in paths:
            try:
                reports.append(self.run(path, **kwargs))
            except Exception as e:
                logger.error(f"Evaluation failed for {path}: {e}")
        return reports


# -- CLI entry point ----------------------------------------------------------
def _cli():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    p = argparse.ArgumentParser(description="AHRAS Dataset Evaluation Runner")
    p.add_argument("--dataset",   required=True, help="Path to CSV file or folder")
    p.add_argument("--limit",     type=int, default=None, help="Max records to evaluate")
    p.add_argument("--sample",    action="store_true",
                   help="With --limit, take a uniform random sample across the WHOLE "
                        "file instead of just the first N rows. Strongly recommended "
                        "for CICIDS2017-style chronologically-ordered files, where "
                        "attacks are concentrated later in the file and head-truncation "
                        "can badly under/over-represent them.")
    p.add_argument("--threshold", type=float, default=20.0,
                   help="AHRAS risk score threshold to classify as attack (default: 20)")
    p.add_argument("--output",    default=None, help="Write JSON report to this file")
    args = p.parse_args()

    runner = EvaluationRunner()
    if os.path.isdir(args.dataset):
        from evaluation.dataset_loader import DatasetLoader
        loaders = DatasetLoader.from_folder(args.dataset)
        reports = []
        for ldr in loaders:
            r = runner.run(ldr.filepath, limit=args.limit, threshold=args.threshold, sample=args.sample)
            reports.append(r.to_dict())
        result = {"reports": reports}
    else:
        report = runner.run(args.dataset, limit=args.limit, threshold=args.threshold, sample=args.sample)
        result = report.to_dict()
        print("\n" + "="*60)
        print(report.summary_line())
        print("="*60)

    if args.output:
        with open(args.output, "w") as f:
            # allow_nan=False: fail loudly if a NaN/Infinity ever slips through
            # again, instead of silently writing invalid JSON (spec-wise) that
            # only breaks downstream when some parser is stricter than
            # Python's json module.
            json.dump(result, f, indent=2, allow_nan=False)
        print(f"\nReport written to {args.output}")
    else:
        print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == "__main__":
    _cli()
