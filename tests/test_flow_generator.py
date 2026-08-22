"""Tests for sensors.flow_generator -- specifically the PPS/BPS divisor fix.

Bug this guards against: FlowRecord.finalise() used to divide by the raw
elapsed duration (floored only at 0.001s). A handful of packets a few
milliseconds apart -- an ordinary DNS query+response, a couple of QUIC/UDP
video-call packets, a browser's rapid ACKs -- would divide out to a "packets
per second" of thousands-to-millions, which is indistinguishable from a real
flood to the signature engine's flood rules and to the trained anomaly
model's [0,1000]-clamped packets_per_second feature. Confirmed live: this
was firing "Traffic Flood"/"UDP Flood"/"Anomalous Behaviour" on completely
ordinary browsing/video-call traffic.
"""
from sensors.flow_generator import FlowRecord


def _make_flow(packet_count, byte_count, start_time, last_seen):
    f = FlowRecord(
        flow_id="test", src_ip="8.8.8.8", dst_ip="10.0.1.61",
        protocol="UDP", src_port=443, dst_port=51000,
        packet_count=packet_count, byte_count=byte_count,
        start_time=start_time, last_seen=last_seen,
    )
    return f


class TestFlowRatesDoNotSpikeOnShortBursts:

    def test_few_packets_over_milliseconds_does_not_explode_pps(self):
        # 4 packets across 8ms -- an ordinary DNS-ish exchange
        f = _make_flow(packet_count=4, byte_count=400, start_time=0.0, last_seen=0.008)
        f.finalise()
        # Old behavior: 4 / 0.008 = 500 pps (== FLOOD_THRESHOLD, a false alarm).
        # Fixed behavior: divisor floored at 1s -> 4 pps.
        assert f.packets_per_second == 4.0
        assert f.packets_per_second < 100  # nowhere near any flood/high-rate threshold

    def test_single_packet_burst_does_not_explode_pps(self):
        f = _make_flow(packet_count=1, byte_count=60, start_time=0.0, last_seen=0.0005)
        f.finalise()
        assert f.packets_per_second == 1.0

    def test_genuine_flood_still_computes_high(self):
        # 800 packets sustained over 1.5s -- a real flood should still trip thresholds.
        f = _make_flow(packet_count=800, byte_count=80000, start_time=0.0, last_seen=1.5)
        f.finalise()
        assert f.packets_per_second > 500  # still clears FLOOD_THRESHOLD default

    def test_duration_field_itself_still_reports_true_elapsed_time(self):
        # duration should stay the real (sub-second) value for reporting/debugging --
        # only the RATE divisor is floored, not the reported duration.
        f = _make_flow(packet_count=3, byte_count=300, start_time=0.0, last_seen=0.01)
        f.finalise()
        assert f.duration == 0.01
