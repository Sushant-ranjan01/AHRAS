"""Tests for detection.signature_engine.engine -- flood-rule packet_count guard.

Belt-and-suspenders alongside the flow_generator.py rate-divisor fix: even
if a FlowRecord somehow arrives with an inflated packets_per_second (e.g.
constructed directly rather than through FlowGenerator), the flood rules
should not fire on a trivial number of packets.
"""
from sensors.flow_generator import FlowRecord
from detection.signature_engine.engine import SignatureEngine


def _flow(**overrides):
    base = dict(
        flow_id="f1", src_ip="8.8.8.8", dst_ip="10.0.1.61",
        protocol="UDP", src_port=443, dst_port=51000,
        packet_count=3, packets_per_second=5000.0, unique_ports=1,
    )
    base.update(overrides)
    return FlowRecord(**base)


class TestFloodRulesRequireRealVolume:

    def test_high_pps_with_trivial_packet_count_does_not_trigger_flood(self):
        eng = SignatureEngine()
        flow = _flow(packet_count=3, packets_per_second=5000.0, protocol="TCP")
        r = eng.analyse(flow)
        assert r.attack_type == "Normal"

    def test_high_pps_with_trivial_packet_count_does_not_trigger_udp_flood(self):
        eng = SignatureEngine()
        flow = _flow(packet_count=3, packets_per_second=200.0, protocol="UDP", unique_ports=1)
        r = eng.analyse(flow)
        assert r.attack_type == "Normal"

    def test_high_pps_with_substantial_packet_count_still_triggers_flood(self):
        eng = SignatureEngine()
        flow = _flow(packet_count=800, packets_per_second=600.0, protocol="TCP")
        r = eng.analyse(flow)
        assert r.attack_type == "Traffic Flood"

    def test_high_pps_with_substantial_packet_count_still_triggers_udp_flood(self):
        eng = SignatureEngine()
        flow = _flow(packet_count=50, packets_per_second=200.0, protocol="UDP", unique_ports=1)
        r = eng.analyse(flow)
        assert r.attack_type == "UDP Flood"
