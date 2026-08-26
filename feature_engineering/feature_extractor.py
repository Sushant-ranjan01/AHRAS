"""AHRAS feature engineering with one canonical normalization path.

This module is the single source of truth for the 17-dimensional anomaly-model
feature vector used by both real-CICIDS baseline training and runtime inference.
"""
from __future__ import annotations

import math
import logging
from dataclasses import dataclass
from typing import Any, Mapping

import numpy as np

from sensors.flow_generator import FlowRecord

logger = logging.getLogger("ahras.features")

FEATURE_NAMES = [
    "packet_count", "byte_count", "unique_ports", "avg_packet_size", "max_packet_size",
    "min_packet_size", "packets_per_second", "bytes_per_second", "duration",
    "protocol_tcp", "protocol_udp", "protocol_icmp", "src_port_norm", "dst_port_norm",
    "syn_flag_ratio", "has_high_dst_port", "is_known_service_port",
]

KNOWN_SVC = {21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 5432, 8080, 8443, 3389}

_NORM = {
    "packet_count": (0, 500),
    "byte_count": (0, 750000),
    "unique_ports": (0, 65535),
    "avg_packet_size": (0, 1500),
    "max_packet_size": (0, 1500),
    "min_packet_size": (0, 1500),
    "packets_per_second": (0, 1000),
    "bytes_per_second": (0, 1500000),
    "duration": (0, 300),
    "src_port_norm": (0, 65535),
    "dst_port_norm": (0, 65535),
}

# Accepted CICIDS/CSE-CIC-IDS2018 naming variants. These are used by the
# baseline importer so its generated vector semantics match runtime extraction.
CICIDS_COLUMN_ALIASES = {
    "dst_port": ["Destination Port", "Dst Port"],
    "src_port": ["Source Port", "Src Port"],
    "protocol": ["Protocol"],
    "flow_duration": ["Flow Duration"],
    "fwd_packets": ["Total Fwd Packets", "Tot Fwd Pkts"],
    "bwd_packets": ["Total Backward Packets", "Tot Bwd Pkts"],
    "fwd_bytes": ["Total Length of Fwd Packets", "TotLen Fwd Pkts"],
    "bwd_bytes": ["Total Length of Bwd Packets", "TotLen Bwd Pkts"],
    "global_max_packet": ["Max Packet Length", "Pkt Len Max"],
    "global_min_packet": ["Min Packet Length", "Pkt Len Min"],
    "fwd_pkt_max": ["Fwd Packet Length Max", "Fwd Pkt Len Max"],
    "bwd_pkt_max": ["Bwd Packet Length Max", "Bwd Pkt Len Max"],
    "fwd_pkt_min": ["Fwd Packet Length Min", "Fwd Pkt Len Min"],
    "bwd_pkt_min": ["Bwd Packet Length Min", "Bwd Pkt Len Min"],
    "avg_packet_size": ["Average Packet Size", "Pkt Size Avg", "Pkt Len Mean"],
    "flow_packets_per_second": ["Flow Packets/s", "Flow Pkts/s"],
    "flow_bytes_per_second": ["Flow Bytes/s", "Flow Byts/s"],
    "syn_count": ["SYN Flag Count", "SYN Flag Cnt"],
    "label": ["Label"],
}


def safe_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    try:
        number = float(value)
    except (ValueError, TypeError):
        return default
    return number if math.isfinite(number) else default


def normalize_value(feature_name: str, value: Any) -> float:
    value = safe_float(value, 0.0)
    if feature_name not in _NORM:
        return float(value)
    lo, hi = _NORM[feature_name]
    if hi == lo:
        return 0.0
    return max(0.0, min(1.0, (value - lo) / (hi - lo)))


def _clean_header(value: Any) -> str:
    return str(value or "").replace("\ufeff", "").strip()


def clean_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {_clean_header(k): v for k, v in row.items() if _clean_header(k)}


def get_alias_value(row: Mapping[str, Any], aliases: list[str], default: Any = None) -> Any:
    for alias in aliases:
        if alias in row and row[alias] not in (None, ""):
            return row[alias]
    return default


def _protocol_string(value: Any) -> str:
    s = str(value or "").strip().lower()
    return {"1": "icmp", "6": "tcp", "17": "udp", "icmp": "icmp", "tcp": "tcp", "udp": "udp"}.get(s, "")


def cicids_row_to_raw_features(row: Mapping[str, Any]) -> dict[str, float]:
    """Convert one CICIDS/CSE-CIC-IDS2018 row to raw AHRAS feature semantics."""
    row = clean_row(row)

    fwd_packets = safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["fwd_packets"]), 0.0)
    bwd_packets = safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["bwd_packets"]), 0.0)
    packet_count = fwd_packets + bwd_packets
    if packet_count <= 0:
        raise ValueError("flow has zero packets")

    fwd_bytes = safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["fwd_bytes"]), 0.0)
    bwd_bytes = safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["bwd_bytes"]), 0.0)
    byte_count = fwd_bytes + bwd_bytes

    duration_us = safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["flow_duration"]), 0.0)
    duration = max(duration_us / 1e6, 0.001)

    pps = safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["flow_packets_per_second"]), 0.0)
    bps = safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["flow_bytes_per_second"]), 0.0)

    avg_pkt = safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["avg_packet_size"]), 0.0)
    if avg_pkt <= 0:
        avg_pkt = byte_count / max(packet_count, 1.0)

    global_max = safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["global_max_packet"]), 0.0)
    if global_max <= 0:
        global_max = max(
            safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["fwd_pkt_max"]), 0.0),
            safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["bwd_pkt_max"]), 0.0),
        )

    global_min = safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["global_min_packet"]), 0.0)
    if global_min <= 0:
        mins = [
            safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["fwd_pkt_min"]), 0.0),
            safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["bwd_pkt_min"]), 0.0),
        ]
        mins = [x for x in mins if x > 0]
        global_min = min(mins) if mins else 0.0

    syn_count = safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["syn_count"]), 0.0)
    syn_ratio = syn_count / max(packet_count, 1.0)

    dst_port = safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["dst_port"]), 0.0)
    src_port = safe_float(get_alias_value(row, CICIDS_COLUMN_ALIASES["src_port"]), 0.0)
    proto = _protocol_string(get_alias_value(row, CICIDS_COLUMN_ALIASES["protocol"], ""))

    # One dataset row is one flow. A single flow cannot provide reliable
    # multi-flow port breadth, so the anomaly feature is explicitly 1.0 here.
    # This MUST match runtime evaluation for CICIDS.
    return {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "unique_ports": 1.0,
        "avg_packet_size": avg_pkt,
        "max_packet_size": global_max,
        "min_packet_size": global_min,
        "packets_per_second": pps,
        "bytes_per_second": bps,
        "duration": duration,
        "protocol_tcp": 1.0 if proto == "tcp" else 0.0,
        "protocol_udp": 1.0 if proto == "udp" else 0.0,
        "protocol_icmp": 1.0 if proto == "icmp" else 0.0,
        "src_port_norm": src_port,
        "dst_port_norm": dst_port,
        "syn_flag_ratio": syn_ratio,
        "has_high_dst_port": 1.0 if dst_port > 1024 else 0.0,
        "is_known_service_port": 1.0 if int(dst_port) in KNOWN_SVC else 0.0,
    }


def raw_features_to_vector(raw: Mapping[str, Any]) -> np.ndarray:
    values = np.asarray([normalize_value(k, raw.get(k, 0.0)) for k in FEATURE_NAMES], dtype=np.float32)
    if not np.all(np.isfinite(values)):
        raise ValueError("non-finite feature vector")
    return values


@dataclass
class FeatureVector:
    flow_id: str
    values: np.ndarray
    raw_flow: FlowRecord


class FlowFeatureExtractor:
    def extract(self, flow: FlowRecord) -> FeatureVector:
        syn = sum(1 for flag in flow.tcp_flags if "S" in str(flag))
        syn_ratio = syn / max(len(flow.tcp_flags), 1)
        raw = {
            "packet_count": safe_float(flow.packet_count),
            "byte_count": safe_float(flow.byte_count),
            "unique_ports": safe_float(flow.unique_ports),
            "avg_packet_size": safe_float(flow.avg_packet_size),
            "max_packet_size": safe_float(flow.max_packet_size),
            "min_packet_size": safe_float(flow.min_packet_size if flow.min_packet_size < 9999 else 0),
            "packets_per_second": safe_float(flow.packets_per_second),
            "bytes_per_second": safe_float(flow.bytes_per_second),
            "duration": safe_float(flow.duration),
            "protocol_tcp": 1.0 if flow.protocol == "TCP" else 0.0,
            "protocol_udp": 1.0 if flow.protocol == "UDP" else 0.0,
            "protocol_icmp": 1.0 if flow.protocol == "ICMP" else 0.0,
            "src_port_norm": safe_float(flow.src_port),
            "dst_port_norm": safe_float(flow.dst_port),
            "syn_flag_ratio": safe_float(syn_ratio),
            "has_high_dst_port": 1.0 if safe_float(flow.dst_port) > 1024 else 0.0,
            "is_known_service_port": 1.0 if int(safe_float(flow.dst_port)) in KNOWN_SVC else 0.0,
        }
        vals = raw_features_to_vector(raw)
        return FeatureVector(flow_id=flow.flow_id, values=vals, raw_flow=flow)


class Preprocessor:
    @staticmethod
    def clean(vec: FeatureVector) -> FeatureVector:
        vec.values = np.nan_to_num(vec.values, nan=0.0, posinf=1.0, neginf=0.0).astype(np.float32)
        if vec.values.shape != (len(FEATURE_NAMES),):
            raise ValueError(f"Expected {len(FEATURE_NAMES)} features, got {vec.values.shape}")
        return vec