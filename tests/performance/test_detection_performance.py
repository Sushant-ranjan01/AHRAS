import os
import statistics
import time

import pytest


@pytest.mark.performance
def test_risk_engine_throughput():
    if os.getenv("AHRAS_RUN_PERF") != "1":
        pytest.skip("Set AHRAS_RUN_PERF=1 to run performance tests")

    from risk_engine.risk_scorer import RiskEngine

    engine = RiskEngine()
    sample = {
        "src_ip": "10.20.30.40",
        "attack_type": "Port Scan",
        "confidence": 0.85,
        "packet_count": 100,
        "unique_ports": 30,
        "syn_count": 50,
        "pps": 200,
        "anomaly_flag": True,
    }

    warmup = 25
    iterations = 500
    for _ in range(warmup):
        engine.evaluate(sample)

    timings = []
    for _ in range(iterations):
        started = time.perf_counter()
        engine.evaluate(sample)
        timings.append(time.perf_counter() - started)

    median_ms = statistics.median(timings) * 1000
    p95_ms = sorted(timings)[int(iterations * 0.95)] * 1000

    # Conservative regression guard for a local CPU; this is not a production SLA.
    assert median_ms < 50, f"Risk engine median latency regressed to {median_ms:.2f} ms"
    assert p95_ms < 100, f"Risk engine p95 latency regressed to {p95_ms:.2f} ms"
