# AHRAS — Test & Evaluation Report (Phase 2)

Generated while testing all 8 Phase-2 modules end-to-end. Every number
below came from actually running code in this repo — nothing here is
estimated or asserted without a command backing it up.

## 1. Functional test results

```
124 passed in 2.11s   (pytest tests/)
```
- 84 pre-existing tests (unchanged, all still pass)
- 37 new tests for the 8 Phase-2 modules (`tests/test_phase2_features.py`)
- 3 new regression tests for a bug found during this testing pass (`tests/test_evaluation.py`)

## 2. Bugs found and fixed during testing

| # | Where | Bug | Fix |
|---|---|---|---|
| 1 | `graph/tgnn.py` | Malicious-hinted edges didn't reliably raise a node's risk energy more than benign edges — pure vector-projection updates aren't monotonic in the boost factor for an arbitrary embedding draw (confirmed via 200-trial stress test, ~50% failure rate before fix). | Added an explicit, monotonically-decaying `_malicious_energy` accumulator blended 50/50 with the embedding-magnitude signal. Re-verified: 0/200 failures after the fix. |
| 2 | `threat_intel/stix_ingestor.py` | STIX hash-pattern parsing (`[file:hashes.'SHA-256' = '...']`) never matched — the regex required a colon before `=`, but hash patterns go straight from the property path to `=` with no colon, unlike ipv4/domain/url patterns. | Split into two regexes: one for `type:value = 'val'` patterns, one for the hash-specific `file:hashes.'ALGO' = 'val'` shape. |
| 3 | `evaluation/runner.py` (**pre-existing**, not part of Phase 2) | `_feature_to_detection()` used the raw **destination port number** (e.g. 443, 8080) as a stand-in for a **count of unique ports contacted** whenever no aggregate field was present. Since real port numbers are almost always >30, this silently added a flat +80 risk bonus to nearly all traffic, benign or not — this alone was responsible for a false-positive rate of 1.00 in an early evaluation run. | Only genuine aggregate-count fields (NSL-KDD's `dst_host_srv_count`/`dst_host_count`) are used now; anything else defaults to 0 rather than substituting a look-alike value. |

## 3. Detection accuracy (synthetic evaluation dataset)

**Why synthetic, not CICIDS2017/NSL-KDD/UNSW-NB15 directly:** those datasets live
on domains outside this sandbox's network allowlist and are multi-GB. A
labeled, CICIDS2017-schema dataset (6,000 flows: benign + DoS/DDoS,
PortScan, SSH/FTP brute-force, Web Attack, Botnet, with 4% injected label
noise so it isn't trivially separable) was generated instead and run
through the project's **real, unmodified** `evaluation.runner.EvaluationRunner`
→ `RiskEngine` → `MetricsCalculator` pipeline — no scoring logic was
mocked. Script: `run_eval_final.py` in this delivery.

**One important methodology note to disclose in your paper:** `RiskEngine`'s
`_rate()`/`_density()`/`_drift()` signals are wall-clock-based (they track
"has this IP been active in the last 30–60 real seconds"), which is
correct for live streaming but means naive batch replay of a dataset with
reused source IPs can artificially inflate risk for benign IPs that
happen to repeat. The numbers below avoid that confound by using a
unique source IP per flow (methodologically standard for per-flow
evaluation) and pre-warming the trust cache to remove real-DNS timing
noise — this is disclosed, not hidden, and is worth a line in your
"Threats to Validity" section either way.

```
Samples:        6,000 (4,200 benign / 1,800 attack)
Accuracy:       0.9703
Precision:      0.9134
Recall:         0.9956
F1:             0.9527
AUC:            0.9731
False Pos Rate: 0.0405
Detection Rate: 0.9956
Confusion:      TP=1792  FP=170  TN=4030  FN=8
```

Per-attack-category breakdown (precision/recall/F1), e.g. DoS GoldenEye
0.995 F1, Bot 0.995 F1 — full breakdown in `eval_final.json`.

## 4. Latency benchmarks

| Component | Latency | Notes |
|---|---|---|
| `RiskEngine.evaluate()` (warm trust cache) | mean 0.01ms, p95 0.016ms, p99 0.032ms | 104,112 events/sec throughput on this sandbox's CPU |
| `_trust()` reverse-DNS, cold (uncached) | ~4.7ms in this sandbox (network-dependent; real-world can be up to the 750ms timeout for a non-responding host) | Only paid once per unique IP; cached after |
| `_trust()`, warm (cached) | 0.015ms | |
| `graph.tgnn.on_edge()` | 0.007ms/call | |
| `graph.tgnn._node_energy()` | 0.002ms/call | |
| `detection.sigma_engine.match()` | 0.0035ms/call (2 rules loaded) | Scales ~linearly with rule count |
| `adaptive_learning.ztre.update_session()` | 0.006ms/call | |
| `honeypot.deception_feedback.handle_hit()` | 0.072ms/call | Includes TTP regex extraction + Sigma rule synthesis |

All Phase-2 additions are sub-millisecond per call — none of them are a
throughput bottleneck relative to the core risk engine.

## 5. What's NOT covered by these numbers (be upfront about this in your papers)

- **No real public benchmark dataset was used** — CICIDS2017/NSL-KDD/UNSW-NB15
  numbers will differ from the synthetic results above and are what reviewers
  will actually want to see. Re-run `evaluation/runner.py` against the real
  files once downloaded outside this sandbox; the harness already supports
  them natively (`DatasetLoader` auto-detects all three formats).
- **`anomaly_flag` in the evaluation mapping is derived directly from the
  dataset's ground-truth label**, not from an independent ML/statistical
  detector run on raw features. This means the reported accuracy is testing
  the risk-fusion math given a mostly-correct detection signal, not raw
  detection-from-network-features end to end. Worth stating explicitly in
  the evaluation section rather than implying it's a from-scratch detector
  accuracy number.
- **eBPF and LLM-copilot paths were exercised only in fallback mode**
  (no root/bcc, no local LLM server running here) — those specific code
  paths are untested in this environment; only the polling/template
  fallbacks were verified.
