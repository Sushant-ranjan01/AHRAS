# ahras/tests/inject_test_events.py
from kafka import KafkaProducer
import json, uuid
from datetime import datetime, timezone

p = KafkaProducer(
    bootstrap_servers="localhost:9092",
    value_serializer=lambda v: json.dumps(v).encode()
)

# Synthetic port scan
for port in range(20, 1024, 10):
    p.send("raw.telemetry", {
        "event_id": str(uuid.uuid4()),
        "source": "network_tap",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": port,
        "protocol": "TCP",
        "packet_count": 1,
        "byte_count": 60,
        "duration_sec": 0.1,
        "tcp_flags": ["SYN"],
        "unique_dst_ports": port,
    })

# Synthetic high-entropy file write (ransomware sim)
p.send("raw.telemetry", {
    "event_id": str(uuid.uuid4()),
    "source": "host_agent",
    "event_type": "file_write",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "filepath": "/home/user/documents/report.docx.enc",
    "entropy": 7.94,
    "high_entropy": True,
    "sha256": "deadbeef" * 8,
    "hostname": "workstation-01",
})

# Suspicious cloud action
p.send("raw.telemetry", {
    "event_id": str(uuid.uuid4()),
    "source": "cloud_adapter",
    "event_type": "cloud_api_call",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "provider": "aws",
    "action": "cloudtrail:StopLogging",
    "severity_hint": "critical",
    "user_identity": "unknown-external",
    "source_ip": "45.33.32.156",
    "region": "us-east-1",
    "user_agent": "python-requests/2.28",
    "request_parameters": {},
    "error_code": None,
})

p.flush()
print("Test events injected.")