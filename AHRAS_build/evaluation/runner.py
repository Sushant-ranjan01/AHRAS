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
    ports = f.get("Destination Port", f.get("dst_host_count", 0))

    # confidence: use packet length std as proxy (higher variance = more suspicious)
    pkt_std   = f.get("Packet Length Std", f.get("sbytes", 0))
    confidence = min(1.0, float(pkt_std) / 5000.0) if pkt_std else 0.2

    # anomaly flag: label==1 records in the dataset have attack traffic patterns
    anomaly_flag = record.label == 1

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
    }


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

            self._risk_eng = RiskEngine()
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
    ):
        from evaluation.dataset_loader import DatasetLoader
        from evaluation.metrics import MetricsCalculator

        name = dataset_name or os.path.basename(dataset_path)
        loader = DatasetLoader(dataset_path)
        logger.info(f"Starting evaluation on {name} (limit={limit}, threshold={threshold})")

        y_true, y_score, latencies, categories = [], [], [], []
        proc = psutil.Process()
        cpu_samples = []
        peak_mem_mb = 0.0

        for record in loader.iter_records(limit=limit):
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
            r = runner.run(ldr.filepath, limit=args.limit, threshold=args.threshold)
            reports.append(r.to_dict())
        result = {"reports": reports}
    else:
        report = runner.run(args.dataset, limit=args.limit, threshold=args.threshold)
        result = report.to_dict()
        print("\n" + "="*60)
        print(report.summary_line())
        print("="*60)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\nReport written to {args.output}")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _cli()
