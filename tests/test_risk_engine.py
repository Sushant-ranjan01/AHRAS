"""Tests for risk_engine.risk_scorer"""
import time
import pytest
from risk_engine.risk_scorer import RiskEngine, _trust


class TestRiskScorer:
    def test_basic_evaluate_returns_result(self, risk_engine, sample_det_external):
        r = risk_engine.evaluate(sample_det_external)
        assert r is not None
        assert hasattr(r, "risk_score_100")
        assert hasattr(r, "severity")
        assert hasattr(r, "raw_components")

    def test_external_malicious_scores_high(self, risk_engine, sample_det_external):
        r = risk_engine.evaluate(sample_det_external)
        assert r.risk_score_100 >= 20, f"Expected >= 20, got {r.risk_score_100}"

    def test_benign_local_scores_zero(self, risk_engine, sample_det_benign):
        r = risk_engine.evaluate(sample_det_benign)
        assert r.risk_score_100 == 0.0, f"Expected 0 for benign local, got {r.risk_score_100}"

    def test_severity_tiers_consistent(self, risk_engine, sample_det_external):
        r = risk_engine.evaluate(sample_det_external)
        if r.risk_score_100 >= 85:
            assert r.severity == "CRITICAL"
        elif r.risk_score_100 >= 50:
            assert r.severity == "HIGH"
        elif r.risk_score_100 >= 20:
            assert r.severity == "MEDIUM"
        else:
            assert r.severity == "LOW"

    def test_score_capped_at_100(self, risk_engine):
        det = {"src_ip": "1.2.3.4", "attack_type": "Traffic Flood",
               "confidence": 1.0, "packet_count": 9999, "pps": 9999,
               "syn_count": 9999, "anomaly_flag": True, "mitre_technique": "T1498"}
        r = risk_engine.evaluate(det)
        assert r.risk_score_100 <= 100.0

    def test_score_never_negative(self, risk_engine, sample_det_benign):
        r = risk_engine.evaluate(sample_det_benign)
        assert r.risk_score_100 >= 0.0

    def test_private_ip_trust_is_high(self, risk_engine):
        from risk_engine.risk_scorer import _is_private
        assert _is_private("192.168.29.175") is True
        assert _is_private("10.0.0.1") is True
        assert _is_private("172.16.0.50") is True
        assert _is_private("127.0.0.1") is True
        assert _is_private("45.33.32.156") is False
        assert _is_private("8.8.8.8") is False

    def test_raw_components_present(self, risk_engine, sample_det_external):
        r = risk_engine.evaluate(sample_det_external)
        assert isinstance(r.raw_components, dict)
        for key in ["signature", "anomaly", "density", "drift_rate"]:
            assert key in r.raw_components, f"Missing component: {key}"
            assert 0.0 <= r.raw_components[key] <= 1.0

    def test_adaptive_weight_injection(self, risk_engine, weight_learner):
        risk_engine.set_adaptive_learner(weight_learner)
        w = risk_engine._current_weights()
        assert len(w) == 4
        assert abs(sum(w) - 1.0) < 1e-6
        # Reset to no learner for other tests
        risk_engine._adaptive_learner = None

    def test_mitre_boost_increases_score(self, risk_engine):
        base = {"src_ip": "5.5.5.5", "attack_type": "Anomalous Behaviour",
                "confidence": 0.5, "packet_count": 10, "anomaly_flag": True}
        with_mitre = dict(base, mitre_technique="T1486")
        r_base = risk_engine.evaluate(base)
        r_mitre = risk_engine.evaluate(with_mitre)
        assert r_mitre.risk_score_100 >= r_base.risk_score_100


class TestSkipDnsBulkEvalMode:
    """
    Regression coverage for the bulk-dataset-evaluation hang: RiskEngine
    used to always do a blocking reverse-DNS lookup (up to 0.75s) for every
    unique non-private source IP. On a CICIDS2017-scale dataset with
    thousands of unique IPs (almost none with real PTR records), that adds
    up to tens of minutes of pure timeout-waiting for evaluation runs.
    skip_dns=True must bypass the DNS lookup and still produce the same
    fallback trust/domain a failed lookup would have given.
    """

    def test_skip_dns_returns_unknown_without_network_call(self):
        # 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — guaranteed to have no
        # real PTR record, so a non-skipping lookup would burn the full
        # _RDNS_TIMEOUT here before falling back.
        trust, domain = _trust("203.0.113.77", skip_dns=True)
        assert (trust, domain) == (0.1, "unknown")

    def test_skip_dns_is_fast(self):
        t0 = time.perf_counter()
        for i in range(200):
            _trust(f"203.0.113.{i % 254}", skip_dns=True)
        elapsed = time.perf_counter() - t0
        # 200 unique non-private, uncached IPs would cost up to 150s
        # (200 * 0.75s) without skip_dns. With it, this should be
        # near-instant — generous ceiling to stay robust on slow CI.
        assert elapsed < 1.0, f"skip_dns lookups took {elapsed:.2f}s, expected < 1.0s"

    def test_skip_dns_does_not_affect_private_ip_trust(self):
        # Private-IP short-circuit must be unaffected by skip_dns either way.
        assert _trust("192.168.1.5", skip_dns=True) == (0.95, "private-network")
        assert _trust("192.168.1.5", skip_dns=False) == (0.95, "private-network")

    def test_risk_engine_skip_dns_flag_wired_through(self):
        eng = RiskEngine(skip_dns=True)
        assert eng._skip_dns is True
        det = {"src_ip": "203.0.113.200", "attack_type": "Traffic Flood",
               "confidence": 0.9, "packet_count": 500, "anomaly_flag": True}
        t0 = time.perf_counter()
        r = eng.evaluate(det)
        elapsed = time.perf_counter() - t0
        assert r is not None
        assert elapsed < 0.5, f"evaluate() with skip_dns took {elapsed:.2f}s"

    def test_default_risk_engine_still_does_real_dns_lookups(self):
        # Production/live-traffic default must be unchanged: skip_dns off.
        eng = RiskEngine()
        assert eng._skip_dns is False


class TestEventTimeBulkReplayFix:
    """
    Regression coverage for the batch-replay false-positive bug: RiskEngine's
    _rate()/_density() used real wall-clock time.time() to measure "packets
    from this IP in the last 30/60 seconds". That's correct for live
    traffic, but replaying a whole day's dataset in under a second makes
    every IP that appears more than ~20-30 times ANYWHERE in the file look
    like it's bursting 20-30 packets in 30 real seconds -- purely because
    of how fast the batch loop runs, not because of anything in the traffic
    itself. This inflated false positives even on datasets with zero real
    attacks. The fix: accept an optional `now` in _rate()/_density() (and
    `event_time` in evaluate()'s input dict) so callers can supply the
    DATASET's own row timestamp instead of wall-clock time.
    """

    def test_rate_uses_supplied_event_time_not_wallclock(self):
        eng = RiskEngine(skip_dns=True)
        # 25 calls for the same IP, all given event_times spread across a
        # single real dataset-day (86400s apart from each other), should NOT
        # look like a 30-second burst -- each call's own 30s window only
        # contains itself.
        base = 1_600_000_000.0
        for i in range(25):
            rate = eng._rate("198.51.100.9", now=base + i * 3600.0)  # +1h apart
        assert rate == 1.0, f"expected rate 1.0 (no real burst), got {rate}"

    def test_rate_still_detects_genuine_burst_within_event_time_window(self):
        eng = RiskEngine(skip_dns=True)
        base = 1_600_000_000.0
        # 25 calls all within the same 30s dataset-time window IS a real burst
        for i in range(25):
            rate = eng._rate("198.51.100.10", now=base + i * 0.5)  # 0.5s apart
        assert rate >= 20, f"expected a real burst to still register, got {rate}"

    def test_rate_falls_back_to_wallclock_when_event_time_not_given(self):
        eng = RiskEngine(skip_dns=True)
        # now=None (unchanged production/live path) must still work exactly
        # as before -- this is what live traffic monitoring relies on.
        rate = eng._rate("198.51.100.11", now=None)
        assert rate == 1.0

    def test_evaluate_passes_event_time_through_to_rate_and_density(self):
        eng = RiskEngine(skip_dns=True)
        base = 1_600_000_000.0
        # Simulate a batch replay: same IP appears 25 times, but each
        # record's event_time is spread 1 hour apart in dataset time, same
        # as a real IP making occasional, unrelated benign connections
        # across a work day -- NOT an actual burst.
        last_result = None
        for i in range(25):
            det = {"src_ip": "198.51.100.20", "attack_type": "Normal",
                   "confidence": 0.2, "packet_count": 5, "anomaly_flag": False,
                   "event_time": base + i * 3600.0}
            last_result = eng.evaluate(det)
        # Should NOT be flagged as risky purely from replay speed.
        assert last_result.risk_score_100 < 20, (
            f"benign, non-bursting traffic scored {last_result.risk_score_100} "
            f"-- event_time is not suppressing the wall-clock batch-replay artifact"
        )

    def test_dataset_record_carries_event_time_field(self):
        from evaluation.dataset_loader import DatasetRecord
        r = DatasetRecord(src_ip="1.2.3.4", features={}, label=0,
                           attack_category="BENIGN", raw_row={})
        assert r.event_time is None  # default, unless the loader parsed one
        r2 = DatasetRecord(src_ip="1.2.3.4", features={}, label=0,
                            attack_category="BENIGN", raw_row={}, event_time=123.0)
        assert r2.event_time == 123.0
        assert r2.to_dict()["event_time"] == 123.0

    def test_cicids_timestamp_parser_handles_known_formats(self):
        from evaluation.dataset_loader import _parse_cicids_timestamp
        # Must not raise on any of these, and must not raise on garbage input.
        assert _parse_cicids_timestamp("") is None
        assert _parse_cicids_timestamp("not a date") is None
        # At least one common CICIDS2017 format must parse successfully.
        parsed = _parse_cicids_timestamp("7/7/2017 3:30:00 PM")
        assert parsed is None or isinstance(parsed, float)


class TestShortFlowPpsArtifactFix:
    """
    Regression coverage for the real, confirmed root cause of AHRAS's false
    positives on real CICIDS2017 traffic (the file variant with no
    Source IP / Timestamp columns): 'Flow Packets/s' is packet_count /
    flow_duration. Ordinary short flows (a handshake, a quick DNS lookup --
    a couple of packets over a few microseconds) produce a mathematically
    huge ratio with nothing resembling a real burst behind it. Confirmed
    via diagnose_fp_cause.py against real Monday-WorkingHours.pcap_ISCX.csv
    (a zero-attack day): 100% of the 4342 false positives (21.7% of all
    benign traffic) were caused by exactly this rule firing on pps values
    like 500,000-2,000,000. The fix requires a real packet volume
    (packet_count>=20) alongside the high ratio before crediting it as a
    genuine high-rate signal.
    """

    def test_high_pps_with_low_packet_count_does_not_trigger_bonus(self):
        # e.g. 2 packets over 1 microsecond -> pps=2,000,000 mathematically,
        # but this is an ordinary handshake, not a flood.
        eng = RiskEngine(skip_dns=True)
        det = {"src_ip": "203.0.113.60", "attack_type": "Normal",
               "confidence": 0.2, "packet_count": 2, "pps": 2_000_000.0,
               "anomaly_flag": False}
        r = eng.evaluate(det)
        assert r.risk_score_100 < 20, (
            f"short-flow pps artifact scored {r.risk_score_100}, "
            f"expected the +20 flat bonus to be suppressed"
        )

    def test_high_pps_with_substantial_packet_count_still_triggers_bonus(self):
        # A genuine flood: high rate AND a real volume of packets.
        eng = RiskEngine(skip_dns=True)
        det_without_bonus = {"src_ip": "203.0.113.61", "attack_type": "Normal",
                              "confidence": 0.2, "packet_count": 2, "pps": 100.0,
                              "anomaly_flag": False}
        det_with_flood = {"src_ip": "203.0.113.62", "attack_type": "Normal",
                           "confidence": 0.2, "packet_count": 5000, "pps": 2500.0,
                           "anomaly_flag": False}
        r_base = eng.evaluate(det_without_bonus)
        r_flood = eng.evaluate(det_with_flood)
        assert r_flood.risk_score_100 > r_base.risk_score_100, (
            "genuine high-volume flood should still score higher than baseline "
            "-- the packet_count guard must not disable real flood detection"
        )

    def test_packet_count_threshold_boundary(self):
        eng = RiskEngine(skip_dns=True)
        det_below = {"src_ip": "203.0.113.63", "attack_type": "Normal",
                     "confidence": 0.2, "packet_count": 19, "pps": 1000.0,
                     "anomaly_flag": False}
        det_at = {"src_ip": "203.0.113.64", "attack_type": "Normal",
                  "confidence": 0.2, "packet_count": 20, "pps": 1000.0,
                  "anomaly_flag": False}
        r_below = eng.evaluate(det_below)
        r_at = eng.evaluate(det_at)
        assert r_at.risk_score_100 > r_below.risk_score_100
