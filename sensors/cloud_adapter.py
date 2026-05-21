"""
Pulls cloud audit logs (AWS CloudTrail format) and publishes to Kafka.
In dev mode, generates synthetic cloud events for testing.
"""

import json
import uuid
import time
import random
import logging
from datetime import datetime, timezone
from kafka import KafkaProducer
from config.settings import KAFKA_BOOTSTRAP, KAFKA_TOPIC_RAW

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CLOUD] %(message)s")
log = logging.getLogger(__name__)

# Synthetic event templates for development/testing
_ACTIONS = [
    ("s3:GetObject",       "low"),
    ("s3:PutObject",       "low"),
    ("iam:CreateUser",     "high"),
    ("iam:AttachUserPolicy","high"),
    ("ec2:AuthorizeSecurityGroupIngress", "medium"),
    ("sts:AssumeRole",     "medium"),
    ("s3:DeleteBucket",    "high"),
    ("cloudtrail:StopLogging", "critical"),    # attacker covering tracks
    ("iam:CreateAccessKey","high"),
]

_USERS = ["alice@corp.com", "bob@corp.com", "svc-deploy", "svc-backup",
           "admin@corp.com", "unknown-external"]

_REGIONS = ["us-east-1", "ap-south-1", "eu-west-1"]


def _synthetic_cloud_event() -> dict:
    action, severity = random.choice(_ACTIONS)
    return {
        "event_id": str(uuid.uuid4()),
        "source": "cloud_adapter",
        "event_type": "cloud_api_call",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "provider": "aws",
        "action": action,
        "severity_hint": severity,
        "user_identity": random.choice(_USERS),
        "source_ip": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
        "region": random.choice(_REGIONS),
        "user_agent": random.choice(["aws-cli/2.x", "boto3/1.x", "Terraform/1.x"]),
        "request_parameters": {},
        "error_code": random.choice([None, None, None, "AccessDenied", "NoSuchKey"]),
    }


def start_cloud_adapter(synthetic: bool = True, interval: float = 3.0):
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=5,
    )
    log.info(f"Cloud adapter started (synthetic={synthetic})")

    while True:
        if synthetic:
            event = _synthetic_cloud_event()
            producer.send(KAFKA_TOPIC_RAW, value=event)
            log.info(f"Cloud event: {event['action']} by {event['user_identity']}")
        time.sleep(interval)


if __name__ == "__main__":
    start_cloud_adapter(synthetic=True, interval=2.0)