"""
Consumes raw.telemetry from Kafka, normalizes every event to OCSF schema,
enriches with GeoIP + threat intel, then writes to:
  - Kafka topic: normalized.events
  - MongoDB collection: events
"""

import json
import uuid
import logging
import requests
from datetime import datetime, timezone

from kafka import KafkaConsumer, KafkaProducer
from pymongo import MongoClient

from config.settings import (
    KAFKA_BOOTSTRAP, KAFKA_TOPIC_RAW, KAFKA_TOPIC_NORMALIZED,
    MONGO_URI, MONGO_DB, MONGO_COLLECTION_EVENTS,
    GEO_API_URL, ABUSEIPDB_KEY,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [NORMALIZER] %(message)s")
log = logging.getLogger(__name__)

# Simple in-memory GeoIP cache to avoid hammering the API
_geo_cache: dict = {}
_abuse_cache: dict = {}


def _geoip(ip: str) -> dict:
    """Enrich an IP address with geolocation data."""
    if ip in _geo_cache:
        return _geo_cache[ip]
    if ip.startswith(("10.", "192.168.", "172.")):
        return {"country": "internal", "city": "", "org": "internal", "lat": 0, "lon": 0}
    try:
        r = requests.get(GEO_API_URL.format(ip=ip), timeout=3)
        data = r.json()
        result = {
            "country": data.get("country", ""),
            "city": data.get("city", ""),
            "org": data.get("org", ""),
            "lat": data.get("lat", 0),
            "lon": data.get("lon", 0),
        }
        _geo_cache[ip] = result
        return result
    except Exception:
        return {"country": "", "city": "", "org": "", "lat": 0, "lon": 0}


def _abuse_score(ip: str) -> int:
    """Returns AbuseIPDB confidence score 0–100. Requires API key."""
    if not ABUSEIPDB_KEY or ip.startswith(("10.", "192.168.", "172.")):
        return 0
    if ip in _abuse_cache:
        return _abuse_cache[ip]
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 30},
            timeout=3,
        )
        score = r.json().get("data", {}).get("abuseConfidenceScore", 0)
        _abuse_cache[ip] = score
        return score
    except Exception:
        return 0


# ── OCSF category mapping ──────────────────────────────────────────────────
# OCSF class IDs: 1001=Network, 1002=Host Process, 1003=File, 4001=Cloud API

def _normalize_network(raw: dict) -> dict:
    src_ip = raw.get("src_ip", "")
    dst_ip = raw.get("dst_ip", "")
    geo = _geoip(src_ip)
    abuse = _abuse_score(src_ip)

    return {
        # OCSF base fields
        "ocsf_class_id": 1001,
        "ocsf_class": "network_activity",
        "event_id": raw.get("event_id", str(uuid.uuid4())),
        "time": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "severity_id": 1,               # will be updated by risk engine
        # Network-specific
        "src_endpoint": {
            "ip": src_ip,
            "port": raw.get("src_port", 0),
            "geo": geo,
        },
        "dst_endpoint": {
            "ip": dst_ip,
            "port": raw.get("dst_port", 0),
        },
        "protocol": raw.get("protocol", "OTHER"),
        "traffic": {
            "packets": raw.get("packet_count", 0),
            "bytes": raw.get("byte_count", 0),
            "duration_sec": raw.get("duration_sec", 0),
        },
        "tcp_flags": raw.get("tcp_flags", []),
        "unique_dst_ports": raw.get("unique_dst_ports", 0),
        # Enrichment
        "enrichment": {
            "geo": geo,
            "abuse_score": abuse,
            "is_threat_intel_hit": abuse > 50,
        },
        "raw_source": "network_tap",
    }


def _normalize_process(raw: dict) -> dict:
    return {
        "ocsf_class_id": 1002,
        "ocsf_class": "process_activity",
        "event_id": raw.get("event_id", str(uuid.uuid4())),
        "time": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "severity_id": 1,
        "actor": {
            "process": {
                "pid": raw.get("pid"),
                "name": raw.get("name", ""),
                "exe": raw.get("exe", ""),
                "cmd_line": raw.get("cmdline", ""),
                "user": {"name": raw.get("username", "")},
            }
        },
        "process": {
            "parent_pid": raw.get("parent_pid"),
            "parent_name": raw.get("parent_name", ""),
        },
        "device": {"hostname": raw.get("hostname", "")},
        "enrichment": {
            "suspicious_lineage": raw.get("suspicious_lineage", False),
        },
        "raw_source": "host_agent",
    }


def _normalize_file(raw: dict) -> dict:
    return {
        "ocsf_class_id": 1003,
        "ocsf_class": "file_activity",
        "event_id": raw.get("event_id", str(uuid.uuid4())),
        "time": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "severity_id": 2 if raw.get("high_entropy") else 1,
        "file": {
            "path": raw.get("filepath", ""),
            "sha256": raw.get("sha256", ""),
        },
        "enrichment": {
            "entropy": raw.get("entropy", 0.0),
            "high_entropy": raw.get("high_entropy", False),
            "ransomware_indicator": raw.get("entropy", 0) > 7.2,
        },
        "device": {"hostname": raw.get("hostname", "")},
        "raw_source": "host_agent",
    }


def _normalize_cloud(raw: dict) -> dict:
    severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return {
        "ocsf_class_id": 4001,
        "ocsf_class": "cloud_api",
        "event_id": raw.get("event_id", str(uuid.uuid4())),
        "time": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "severity_id": severity_map.get(raw.get("severity_hint", "low"), 1),
        "api": {
            "operation": raw.get("action", ""),
            "request": raw.get("request_parameters", {}),
            "response": {"error": raw.get("error_code")},
        },
        "actor": {
            "user": {"name": raw.get("user_identity", "")},
        },
        "src_endpoint": {
            "ip": raw.get("source_ip", ""),
            "geo": _geoip(raw.get("source_ip", "")),
        },
        "cloud": {
            "provider": raw.get("provider", ""),
            "region": raw.get("region", ""),
        },
        "enrichment": {
            "high_privilege_action": raw.get("severity_hint") in ("high", "critical"),
        },
        "raw_source": "cloud_adapter",
    }


_NORMALIZERS = {
    "network_tap": _normalize_network,
    "host_agent": {
        "process_spawn": _normalize_process,
        "network_conn": _normalize_network,
        "file_write": _normalize_file,
    },
    "cloud_adapter": _normalize_cloud,
}


def _route(raw: dict) -> dict | None:
    source = raw.get("source", "")
    event_type = raw.get("event_type", "")

    if source == "network_tap":
        return _normalize_network(raw)
    elif source == "host_agent":
        handler = _NORMALIZERS["host_agent"].get(event_type)
        return handler(raw) if handler else None
    elif source == "cloud_adapter":
        return _normalize_cloud(raw)
    return None


def start_normalizer():
    consumer = KafkaConsumer(
        KAFKA_TOPIC_RAW,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        group_id="ahras-normalizer",
        auto_offset_reset="earliest",
    )
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    mongo = MongoClient(MONGO_URI)[MONGO_DB][MONGO_COLLECTION_EVENTS]
    mongo.create_index("time")
    mongo.create_index("ocsf_class")
    mongo.create_index("enrichment.is_threat_intel_hit")

    log.info("Normalizer running — consuming raw.telemetry")

    for msg in consumer:
        raw = msg.value
        try:
            normalized = _route(raw)
            if normalized is None:
                continue

            # Publish to normalized topic
            producer.send(KAFKA_TOPIC_NORMALIZED, value=normalized)

            # Write to MongoDB
            mongo.insert_one({**normalized, "_id": normalized["event_id"]})

            log.info(
                f"[{normalized['ocsf_class']}] "
                f"{normalized.get('src_endpoint', {}).get('ip', '')} "
                f"severity={normalized['severity_id']}"
            )
        except Exception as e:
            log.error(f"Normalization failed: {e} | raw={raw}")


if __name__ == "__main__":
    start_normalizer()