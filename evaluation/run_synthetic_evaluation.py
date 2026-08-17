"""
Evaluation driver for AHRAS's RiskEngine on the synthetic dataset.

Why this exists rather than just calling `python -m evaluation.runner`
directly: RiskEngine._trust() does a REAL reverse-DNS lookup (0.75s
timeout) for every never-before-seen public IP. That's correct and
desirable in production (trust decisions should reflect real
reachability/reputation), but it means a batch evaluation over thousands
of unique synthetic IPs mostly measures DNS resolver latency, not
detection accuracy. Two ways to remove that confound:
  (a) reuse a small IP pool so the cache warms up -- but that then
      confounds RiskEngine's wall-clock-based rate/density/drift signals
      (which assume "same IP seen again" means "same attacker acting
      again over time", not "dataset replay happens to repeat this IP"),
  (b) pre-populate the trust cache directly before timing -- keeps every
      row on a genuinely unique IP (methodologically correct for
      per-flow evaluation) while removing DNS as a variable.
This script does (b): every synthetic IP is pre-classified as "unknown
public" (trust=0.1) since none of them are expected to reverse-resolve
to a real trusted domain anyway -- that's the same outcome the real rDNS
lookup would eventually produce for genuinely random IPs, just without
paying the 0.75s timeout thousands of times over.
"""
import csv
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from risk_engine.risk_scorer import _TRUST_CACHE
from evaluation.runner import EvaluationRunner

DATASET = os.path.join(os.path.dirname(__file__), "synthetic_data", "synthetic_cicids_style.csv")

# Pre-warm the trust cache for every unique source IP in the dataset.
with open(DATASET) as f:
    reader = csv.DictReader(f)
    ips = {row["Source IP"] for row in reader}

for ip in ips:
    _TRUST_CACHE[ip] = (0.1, "unknown")

print(f"Pre-warmed trust cache for {len(ips)} unique synthetic IPs (no real DNS calls made)")

runner = EvaluationRunner()

t0 = time.time()
report = runner.run(dataset_path=DATASET, limit=6000, threshold=20.0)
elapsed = time.time() - t0

print(f"\nEvaluation wall time: {elapsed:.1f}s for 6000 records "
      f"({6000/elapsed:.0f} records/sec)")
print(report.summary_line())

out_path = os.path.join(os.path.dirname(__file__), "synthetic_data", "eval_report.json")
with open(out_path, "w") as f:
    json.dump(report.to_dict(), f, indent=2)
print(f"Full report written to {out_path}")
