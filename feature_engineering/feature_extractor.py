"""AHRAS — Feature Engineering (Phase 3)"""
import numpy as np, logging
from dataclasses import dataclass
from typing import List
from sensors.flow_generator import FlowRecord

logger = logging.getLogger("ahras.features")

FEATURE_NAMES = [
    "packet_count","byte_count","unique_ports","avg_packet_size","max_packet_size",
    "min_packet_size","packets_per_second","bytes_per_second","duration",
    "protocol_tcp","protocol_udp","protocol_icmp","src_port_norm","dst_port_norm",
    "syn_flag_ratio","has_high_dst_port","is_known_service_port",
]
KNOWN_SVC = {21,22,23,25,53,80,110,143,443,3306,5432,8080,8443,3389}
_NORM = {
    "packet_count":(0,500),"byte_count":(0,750000),"unique_ports":(0,65535),
    "avg_packet_size":(0,1500),"max_packet_size":(0,1500),"min_packet_size":(0,1500),
    "packets_per_second":(0,1000),"bytes_per_second":(0,1500000),"duration":(0,300),
    "src_port_norm":(0,65535),"dst_port_norm":(0,65535),
}

@dataclass
class FeatureVector:
    flow_id: str
    values: np.ndarray
    raw_flow: FlowRecord

class FlowFeatureExtractor:
    def extract(self, flow: FlowRecord) -> FeatureVector:
        syn = sum(1 for f in flow.tcp_flags if "S" in str(f))
        syn_ratio = syn / max(len(flow.tcp_flags),1)
        raw = {
            "packet_count": flow.packet_count, "byte_count": flow.byte_count,
            "unique_ports": flow.unique_ports, "avg_packet_size": flow.avg_packet_size,
            "max_packet_size": flow.max_packet_size,
            "min_packet_size": flow.min_packet_size if flow.min_packet_size < 9999 else 0,
            "packets_per_second": flow.packets_per_second, "bytes_per_second": flow.bytes_per_second,
            "duration": flow.duration,
            "protocol_tcp":  1.0 if flow.protocol=="TCP"  else 0.0,
            "protocol_udp":  1.0 if flow.protocol=="UDP"  else 0.0,
            "protocol_icmp": 1.0 if flow.protocol=="ICMP" else 0.0,
            "src_port_norm": flow.src_port, "dst_port_norm": flow.dst_port,
            "syn_flag_ratio": syn_ratio,
            "has_high_dst_port": 1.0 if flow.dst_port > 1024 else 0.0,
            "is_known_service_port": 1.0 if flow.dst_port in KNOWN_SVC else 0.0,
        }
        vals = np.array([self._norm(k, raw[k]) for k in FEATURE_NAMES], dtype=np.float32)
        return FeatureVector(flow_id=flow.flow_id, values=vals, raw_flow=flow)

    def _norm(self, k, v):
        if k not in _NORM: return float(v)
        lo,hi = _NORM[k]
        return max(0.0, min(1.0, (v-lo)/(hi-lo) if hi!=lo else 0.0))

class Preprocessor:
    @staticmethod
    def clean(vec: FeatureVector) -> FeatureVector:
        vec.values = np.nan_to_num(vec.values, nan=0.0, posinf=1.0, neginf=0.0)
        return vec
