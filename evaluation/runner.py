"""
AHRAS v5 — Evaluation Runner
============================

Feeds DatasetLoader records through:

    DatasetLoader
        -> FlowRecord
        -> HybridDetectionEngine
        -> RiskEngine
        -> MetricsCalculator

Important evaluation rules:
- Ground-truth labels never enter detection or risk scoring.
- Destination port is NOT treated as unique-port count.
- Aggregate port-breadth fields are used only when the dataset actually
  provides them (e.g. NSL-KDD).
- CICIDS per-flow records default to unique_ports=0 because one flow does
  not provide reliable multi-flow port breadth.
- Dataset event timestamps are passed into RiskEngine for temporal replay.
- Continuous anomaly evidence is preserved and passed to RiskEngine.
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


# ---------------------------------------------------------------------------
# DatasetRecord -> FlowRecord
# ---------------------------------------------------------------------------

def _record_to_flow(record):
    """
    Convert a DatasetRecord into the FlowRecord expected by the real
    HybridDetectionEngine.

    IMPORTANT:
    record.label and record.attack_category are ground truth and MUST NOT
    enter the detection path.
    """
    from sensors.flow_generator import FlowRecord

    f = record.features

    # -----------------------------------------------------------------------
    # Packet counts
    # -----------------------------------------------------------------------
    fwd = f.get("Total Fwd Packets", 0)
    if not fwd:
        fwd = f.get("spkts", 0)

    bwd = f.get("Total Backward Packets", 0)
    if not bwd:
        bwd = f.get("dpkts", 0)

    try:
        fwd = float(fwd or 0)
    except (TypeError, ValueError):
        fwd = 0.0

    try:
        bwd = float(bwd or 0)
    except (TypeError, ValueError):
        bwd = 0.0

    pkt = int(fwd + bwd)

    if pkt <= 0:
        try:
            pkt = int(float(f.get("count", 0) or 0))
        except (TypeError, ValueError):
            pkt = 0

    # -----------------------------------------------------------------------
    # Flow rates
    # -----------------------------------------------------------------------
    try:
        bps = float(
            f.get(
                "Flow Bytes/s",
                float(f.get("sload", 0) or 0)
                + float(f.get("dload", 0) or 0),
            )
            or 0
        )
    except (TypeError, ValueError):
        bps = 0.0

    try:
        pps = float(
            f.get(
                "Flow Packets/s",
                f.get("rate", 0),
            )
            or 0
        )
    except (TypeError, ValueError):
        pps = 0.0

    # -----------------------------------------------------------------------
    # Duration
    # CICIDS duration is commonly microseconds.
    # NSL/UNSW durations are already in seconds.
    # -----------------------------------------------------------------------
    try:
        flow_duration = float(f.get("Flow Duration", 0) or 0)
    except (TypeError, ValueError):
        flow_duration = 0.0

    try:
        generic_duration = float(f.get("dur", 0) or 0)
    except (TypeError, ValueError):
        generic_duration = 0.0

    if flow_duration > 0:
        dur = max(flow_duration / 1e6, 0.001)
    elif generic_duration > 0:
        dur = max(generic_duration, 0.001)
    else:
        dur = 0.001

    if not pps and pkt > 0:
        pps = pkt / dur

    # -----------------------------------------------------------------------
    # SYN count
    # -----------------------------------------------------------------------
    try:
        syns = int(float(f.get("SYN Flag Count", 0) or 0))
    except (TypeError, ValueError):
        syns = 0

    # -----------------------------------------------------------------------
    # UNIQUE PORT COUNT
    #
    # A destination port number (e.g. 443) is NOT the number of unique ports.
    #
    # CICIDS per-flow records do not provide a reliable multi-flow scan
    # breadth value, so use 0.
    #
    # NSL-KDD may provide aggregate host-count features. Preserve those
    # when present.
    # -----------------------------------------------------------------------
    if "dst_host_srv_count" in f:
        try:
            ports = int(float(f.get("dst_host_srv_count", 0) or 0))
        except (TypeError, ValueError):
            ports = 0
    elif "dst_host_count" in f:
        try:
            ports = int(float(f.get("dst_host_count", 0) or 0))
        except (TypeError, ValueError):
            ports = 0
    else:
        ports = 0

    # Never use destination port itself as unique_ports.
    ports = max(0, ports)

    # -----------------------------------------------------------------------
    # Byte count
    # -----------------------------------------------------------------------
    try:
        fwd_bytes = float(f.get("Total Length of Fwd Packets", 0) or 0)
    except (TypeError, ValueError):
        fwd_bytes = 0.0

    try:
        bwd_bytes = float(f.get("Total Length of Bwd Packets", 0) or 0)
    except (TypeError, ValueError):
        bwd_bytes = 0.0

    byte_count = int(fwd_bytes + bwd_bytes)

    if byte_count <= 0:
        try:
            sbytes = float(f.get("sbytes", 0) or 0)
        except (TypeError, ValueError):
            sbytes = 0.0

        try:
            dbytes = float(f.get("dbytes", 0) or 0)
        except (TypeError, ValueError):
            dbytes = 0.0

        byte_count = int(sbytes + dbytes)

    if byte_count <= 0 and bps > 0 and dur > 0:
        byte_count = int(bps * dur)

    byte_count = max(0, byte_count)

    # -----------------------------------------------------------------------
    # Packet sizes
    # -----------------------------------------------------------------------
    try:
        max_pkt = float(f.get("Max Packet Length", 0) or 0)
    except (TypeError, ValueError):
        max_pkt = 0.0

    try:
        min_pkt = float(f.get("Min Packet Length", 0) or 0)
    except (TypeError, ValueError):
        min_pkt = 0.0

    try:
        avg_pkt = float(f.get("Average Packet Size", 0) or 0)
    except (TypeError, ValueError):
        avg_pkt = 0.0

    if avg_pkt <= 0 and pkt > 0:
        avg_pkt = byte_count / pkt

    # -----------------------------------------------------------------------
    # Protocol
    # -----------------------------------------------------------------------
    proto_num = f.get("Protocol", None)

    try:
        proto_num_int = int(float(proto_num))
    except (TypeError, ValueError):
        proto_num_int = None

    if isinstance(proto_num, str):
        protocol_text = proto_num.strip().upper()
        protocol = {
            "TCP": "TCP",
            "UDP": "UDP",
            "ICMP": "ICMP",
        }.get(protocol_text, "TCP")
    else:
        protocol = {
            6: "TCP",
            17: "UDP",
            1: "ICMP",
        }.get(proto_num_int, "TCP")

    # -----------------------------------------------------------------------
    # Destination port
    # -----------------------------------------------------------------------
    try:
        dst_port = int(float(f.get("Destination Port", 0) or 0))
    except (TypeError, ValueError):
        dst_port = 0

    # -----------------------------------------------------------------------
    # TCP flags
    # -----------------------------------------------------------------------
    syn_count_for_flags = max(0, min(syns, pkt))
    tcp_flags = (
        (["S"] * syn_count_for_flags)
        + (["A"] * max(pkt - syn_count_for_flags, 0))
    )

    # -----------------------------------------------------------------------
    # Build FlowRecord
    # -----------------------------------------------------------------------
    flow = FlowRecord(
        flow_id=f"eval-{record.src_ip}-{id(record)}",
        src_ip=record.src_ip,
        dst_ip="0.0.0.0",
        protocol=protocol,
        src_port=0,
        dst_port=dst_port,
        packet_count=pkt,
        byte_count=byte_count,
        unique_dst_ports=set(),
        tcp_flags=tcp_flags,
        avg_packet_size=avg_pkt,
        max_packet_size=int(max_pkt) if max_pkt > 0 else 0,
        min_packet_size=int(min_pkt) if min_pkt > 0 else 0,
        duration=dur,
        packets_per_second=max(0.0, pps),
        bytes_per_second=max(0.0, bps),
    )

    # Port-breadth count is separate from destination port number.
    flow.unique_ports = ports

    # Keep a set only when a real aggregate count exists.
    if ports > 0:
        flow.unique_dst_ports = set(range(ports))

    return flow


# ---------------------------------------------------------------------------
# DetectionResult -> RiskEngine input
# ---------------------------------------------------------------------------

def _detection_to_risk_input(record, det_result) -> dict:
    """
    Convert a genuine DetectionResult plus row-derived traffic aggregates
    into the dictionary expected by RiskEngine.

    Ground truth is never used here.
    """

    f = record.features

    # -----------------------------------------------------------------------
    # Packet count
    # -----------------------------------------------------------------------
    try:
        fwd = float(f.get("Total Fwd Packets", 0) or 0)
    except (TypeError, ValueError):
        fwd = 0.0

    if not fwd:
        try:
            fwd = float(f.get("spkts", 0) or 0)
        except (TypeError, ValueError):
            fwd = 0.0

    try:
        bwd = float(f.get("Total Backward Packets", 0) or 0)
    except (TypeError, ValueError):
        bwd = 0.0

    if not bwd:
        try:
            bwd = float(f.get("dpkts", 0) or 0)
        except (TypeError, ValueError):
            bwd = 0.0

    pkt = int(fwd + bwd)

    if pkt <= 0:
        try:
            pkt = int(float(f.get("count", 0) or 0))
        except (TypeError, ValueError):
            pkt = 0

    # -----------------------------------------------------------------------
    # Packet rate
    # -----------------------------------------------------------------------
    try:
        pps = float(f.get("Flow Packets/s", f.get("rate", 0)) or 0)
    except (TypeError, ValueError):
        pps = 0.0

    try:
        flow_duration = float(f.get("Flow Duration", 0) or 0)
    except (TypeError, ValueError):
        flow_duration = 0.0

    try:
        generic_duration = float(f.get("dur", 0) or 0)
    except (TypeError, ValueError):
        generic_duration = 0.0

    if flow_duration > 0:
        dur = max(flow_duration / 1e6, 0.001)
    elif generic_duration > 0:
        dur = max(generic_duration, 0.001)
    else:
        dur = 0.001

    if not pps and pkt > 0:
        pps = pkt / dur

    # -----------------------------------------------------------------------
    # SYN count
    # -----------------------------------------------------------------------
    try:
        syns = int(float(f.get("SYN Flag Count", 0) or 0))
    except (TypeError, ValueError):
        syns = 0

    # -----------------------------------------------------------------------
    # UNIQUE PORT COUNT
    # Same semantics as _record_to_flow().
    # -----------------------------------------------------------------------
    if "dst_host_srv_count" in f:
        try:
            ports = int(float(f.get("dst_host_srv_count", 0) or 0))
        except (TypeError, ValueError):
            ports = 0
    elif "dst_host_count" in f:
        try:
            ports = int(float(f.get("dst_host_count", 0) or 0))
        except (TypeError, ValueError):
            ports = 0
    else:
        ports = 0

    ports = max(0, ports)

    # -----------------------------------------------------------------------
    # Bytes/sec
    # -----------------------------------------------------------------------
    try:
        bps = float(
            f.get(
                "Flow Bytes/s",
                float(f.get("sload", 0) or 0)
                + float(f.get("dload", 0) or 0),
            )
            or 0
        )
    except (TypeError, ValueError):
        bps = 0.0

    # -----------------------------------------------------------------------
    # Anomaly evidence
    #
    # Preserve both:
    # - binary is_anomaly
    # - continuous normalized anomaly score
    # -----------------------------------------------------------------------
    anomaly_result = getattr(det_result, "anomaly_result", None)

    anomaly_flag = (
        bool(anomaly_result.is_anomaly)
        if anomaly_result is not None
        else False
    )

    anomaly_score = (
        float(anomaly_result.normalised_score)
        if anomaly_result is not None
        else 0.0
    )

    # Keep within the expected range.
    anomaly_score = max(0.0, min(1.0, anomaly_score))

    return {
        "src_ip": record.src_ip,

        # Detection result only; never dataset ground truth.
        "attack_type": getattr(det_result, "attack_type", "Normal"),
        "confidence": float(getattr(det_result, "confidence", 0.0)),

        "packet_count": pkt,
        "pps": max(0.0, pps),
        "unique_ports": ports,
        "syn_count": max(0, syns),
        "bytes_per_sec": max(0.0, bps),

        # Anomaly evidence.
        "anomaly_flag": anomaly_flag,
        "anomaly_score": anomaly_score,

        # Dataset timestamp used for causal temporal replay.
        "event_time": getattr(record, "event_time", None),
    }


# ---------------------------------------------------------------------------
# Evaluation Runner
# ---------------------------------------------------------------------------

class EvaluationRunner:
    """
    Orchestrates:

        DatasetLoader
            -> FlowRecord
            -> HybridDetectionEngine
            -> RiskEngine
            -> MetricsCalculator
    """

    def __init__(self):
        self._setup_engines()

    def _setup_engines(self):
        """Initialize the real detection, risk and metric engines."""
        try:
            sys.path.insert(
                0,
                os.path.dirname(os.path.dirname(__file__)),
            )

            from risk_engine.risk_scorer import RiskEngine
            from detection.hybrid_detection import HybridDetectionEngine
            from evaluation.metrics import MetricsCalculator

            self._risk_eng = RiskEngine(skip_dns=True)
            self._detector = HybridDetectionEngine()
            self._calc = MetricsCalculator()

            logger.info("EvaluationRunner engines ready")

        except Exception as e:
            logger.exception("Engine init failed")
            raise RuntimeError(
                f"Could not initialize evaluation engines: {e}"
            ) from e

    # -----------------------------------------------------------------------
    # Main evaluation
    # -----------------------------------------------------------------------

    def run(
        self,
        dataset_path: str,
        limit: Optional[int] = None,
        threshold: float = 20.0,
        dataset_name: Optional[str] = None,
        sample: bool = False,
    ):
        from evaluation.dataset_loader import DatasetLoader

        name = dataset_name or os.path.basename(dataset_path)

        loader = DatasetLoader(dataset_path)

        mode = (
            "reservoir-sampled"
            if (sample and limit)
            else "head-truncated"
            if limit
            else "full-file"
        )

        logger.info(
            f"Starting evaluation on {name} "
            f"(limit={limit}, mode={mode}, threshold={threshold})"
        )

        if limit and not sample:
            logger.warning(
                f"[{name}] limit={limit} with sample=False reads only the FIRST "
                f"{limit} rows. For chronologically ordered datasets, this can "
                f"under-represent attacks. Prefer --sample for evaluation."
            )

        # -------------------------------------------------------------------
        # Metric data
        # -------------------------------------------------------------------
        y_true = []
        y_score = []
        latencies = []
        categories = []

        proc = psutil.Process()

        cpu_samples = []
        peak_mem_mb = 0.0

        evaluation_failures = 0

        # -------------------------------------------------------------------
        # Evaluate rows
        # -------------------------------------------------------------------
        for record in loader.iter_records(
            limit=limit,
            sample=sample,
        ):
            t0 = time.perf_counter()

            score = 0.0

            try:
                # -----------------------------------------------------------
                # DatasetRecord -> FlowRecord
                # -----------------------------------------------------------
                flow = _record_to_flow(record)

                # -----------------------------------------------------------
                # FlowRecord -> real detection model
                # -----------------------------------------------------------
                det_result = self._detector.analyse(flow)

                # -----------------------------------------------------------
                # DetectionResult -> risk input
                # -----------------------------------------------------------
                det_input = _detection_to_risk_input(
                    record,
                    det_result,
                )

                # -----------------------------------------------------------
                # Risk scoring
                # -----------------------------------------------------------
                risk = self._risk_eng.evaluate(det_input)

                score = float(
                    getattr(
                        risk,
                        "risk_score_100",
                        0.0,
                    )
                    or 0.0
                )

                # Safety bound.
                score = max(0.0, min(100.0, score))

            except Exception as e:
                evaluation_failures += 1

                logger.exception(
                    "Detection/risk eval failed for %s: %s",
                    record.src_ip,
                    e,
                )

                # Keep the score at 0 so output remains numerically valid,
                # but track the failure separately instead of pretending
                # this was a genuine low-risk observation.

                score = 0.0

            latency_ms = (
                time.perf_counter() - t0
            ) * 1000.0

            # Ground truth enters ONLY here.
            y_true.append(record.label)
            y_score.append(score)
            latencies.append(latency_ms)
            categories.append(record.attack_category)

            # ---------------------------------------------------------------
            # CPU / memory sampling
            # ---------------------------------------------------------------
            if len(y_true) % 100 == 0:
                cpu_samples.append(
                    proc.cpu_percent(interval=None)
                )

                mem_mb = (
                    proc.memory_info().rss
                    / 1024
                    / 1024
                )

                peak_mem_mb = max(
                    peak_mem_mb,
                    mem_mb,
                )

        # -------------------------------------------------------------------
        # Performance statistics
        # -------------------------------------------------------------------
        mean_cpu = (
            sum(cpu_samples) / len(cpu_samples)
            if cpu_samples
            else 0.0
        )

        # -------------------------------------------------------------------
        # Metrics
        # -------------------------------------------------------------------
        calc = self._calc

        report = calc.compute(
            y_true=y_true,
            y_score=y_score,
            latencies_ms=latencies,
            peak_memory_mb=peak_mem_mb,
            mean_cpu_pct=mean_cpu,
            dataset_name=name,
            threshold=threshold,
            attack_categories=categories,
        )

        # Attach evaluator diagnostics if the report implementation allows
        # arbitrary attributes.
        try:
            report.evaluation_failures = evaluation_failures
            report.samples_evaluated = len(y_true)
        except Exception:
            pass

        logger.info(
            report.summary_line()
        )

        if evaluation_failures:
            logger.warning(
                "[%s] Evaluation completed with %d detection/risk failures "
                "out of %d rows.",
                name,
                evaluation_failures,
                len(y_true),
            )

        return report

    # -----------------------------------------------------------------------
    # Multiple files
    # -----------------------------------------------------------------------

    def run_multiple(
        self,
        paths: list,
        **kwargs,
    ):
        """Run evaluation on multiple dataset files."""
        reports = []

        for path in paths:
            try:
                reports.append(
                    self.run(
                        path,
                        **kwargs,
                    )
                )

            except Exception as e:
                logger.exception(
                    "Evaluation failed for %s: %s",
                    path,
                    e,
                )

        return reports


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="AHRAS Dataset Evaluation Runner"
    )

    parser.add_argument(
        "--dataset",
        required=True,
        help="Path to a CSV file or folder",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum number of records to evaluate",
    )

    parser.add_argument(
        "--sample",
        action="store_true",
        help=(
            "With --limit, use uniform reservoir sampling over the whole file "
            "instead of taking only the first N rows."
        ),
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=20.0,
        help=(
            "AHRAS risk-score threshold to classify as attack "
            "(default: 20)"
        ),
    )

    parser.add_argument(
        "--output",
        default=None,
        help="Write JSON report to this file",
    )

    args = parser.parse_args()

    runner = EvaluationRunner()

    # -----------------------------------------------------------------------
    # Folder evaluation
    # -----------------------------------------------------------------------
    if os.path.isdir(args.dataset):
        from evaluation.dataset_loader import DatasetLoader

        loaders = DatasetLoader.from_folder(
            args.dataset
        )

        reports = []

        for loader in loaders:
            report = runner.run(
                loader.filepath,
                limit=args.limit,
                threshold=args.threshold,
                sample=args.sample,
            )

            reports.append(
                report.to_dict()
            )

        result = {
            "reports": reports
        }

    # -----------------------------------------------------------------------
    # Single file evaluation
    # -----------------------------------------------------------------------
    else:
        report = runner.run(
            args.dataset,
            limit=args.limit,
            threshold=args.threshold,
            sample=args.sample,
        )

        result = report.to_dict()

        print("\n" + "=" * 60)
        print(report.summary_line())
        print("=" * 60)

    # -----------------------------------------------------------------------
    # Output
    # -----------------------------------------------------------------------
    if args.output:
        with open(
            args.output,
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(
                result,
                f,
                indent=2,
                allow_nan=False,
            )

        print(
            f"\nReport written to {args.output}"
        )

    else:
        print(
            json.dumps(
                result,
                indent=2,
                allow_nan=False,
            )
        )


if __name__ == "__main__":
    _cli()