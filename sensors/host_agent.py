"""
Monitors the local host and publishes three event types to Kafka:
  - process_spawn   (process lineage)
  - file_write      (with Shannon entropy for ransomware detection)
  - network_conn    (outbound connections per process)
"""

import json
import uuid
import math
import time
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from kafka import KafkaProducer

from config.settings import KAFKA_BOOTSTRAP, KAFKA_TOPIC_RAW

logging.basicConfig(level=logging.INFO, format="%(asctime)s [HOST] %(message)s")
log = logging.getLogger(__name__)

WATCH_DIRS = ["/home", "/tmp", "/var/tmp"]
ENTROPY_THRESHOLD = 7.2        # bits — encrypted/compressed data is near 8.0
PROCESS_POLL_INTERVAL = 5      # seconds
_seen_pids: set = set()


def _make_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=5,
    )


def _shannon_entropy(filepath: str) -> float:
    """Compute Shannon entropy H(X) = -Σ P(xi) log2 P(xi) for a file."""
    try:
        with open(filepath, "rb") as f:
            data = f.read(65536)   # read first 64 KB — enough for entropy estimate
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        n = len(data)
        entropy = 0.0
        for count in freq:
            if count:
                p = count / n
                entropy -= p * math.log2(p)
        return round(entropy, 4)
    except (PermissionError, FileNotFoundError, OSError):
        return 0.0


def _file_sha256(filepath: str) -> str:
    try:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return ""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class FileWriteHandler(FileSystemEventHandler):
    def __init__(self, producer: KafkaProducer):
        self.producer = producer

    def on_modified(self, event):
        if event.is_directory:
            return
        self._handle(event.src_path)

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle(event.src_path)

    def _handle(self, filepath: str):
        entropy = _shannon_entropy(filepath)
        sha256 = _file_sha256(filepath) if entropy > ENTROPY_THRESHOLD else ""
        event_record = {
            "event_id": str(uuid.uuid4()),
            "source": "host_agent",
            "event_type": "file_write",
            "timestamp": _now_iso(),
            "filepath": filepath,
            "entropy": entropy,
            "high_entropy": entropy > ENTROPY_THRESHOLD,
            "sha256": sha256,
            "hostname": _hostname(),
        }
        self.producer.send(KAFKA_TOPIC_RAW, value=event_record)
        if entropy > ENTROPY_THRESHOLD:
            log.warning(f"HIGH ENTROPY file: {filepath} (H={entropy})")


def _hostname() -> str:
    import socket
    return socket.gethostname()


def _poll_processes(producer: KafkaProducer):
    """Detect new process spawns and record parent-child lineage."""
    global _seen_pids
    current_pids = set(psutil.pids())
    new_pids = current_pids - _seen_pids
    _seen_pids = current_pids

    for pid in new_pids:
        try:
            proc = psutil.Process(pid)
            parent = proc.parent()
            record = {
                "event_id": str(uuid.uuid4()),
                "source": "host_agent",
                "event_type": "process_spawn",
                "timestamp": _now_iso(),
                "hostname": _hostname(),
                "pid": pid,
                "name": proc.name(),
                "exe": proc.exe(),
                "cmdline": " ".join(proc.cmdline()[:20]),
                "parent_pid": parent.pid if parent else None,
                "parent_name": parent.name() if parent else None,
                "username": proc.username(),
            }
            producer.send(KAFKA_TOPIC_RAW, value=record)

            # Flag suspicious lineage (e.g. office app spawning shell)
            suspicious_parents = {"soffice", "libreoffice", "python3", "python",
                                   "node", "java", "php"}
            suspicious_children = {"bash", "sh", "zsh", "nc", "ncat", "wget",
                                    "curl", "perl", "python3"}
            if (parent and parent.name() in suspicious_parents
                    and proc.name() in suspicious_children):
                log.warning(
                    f"SUSPICIOUS LINEAGE: {parent.name()} (pid={parent.pid})"
                    f" → {proc.name()} (pid={pid})"
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass


def _poll_connections(producer: KafkaProducer):
    """Record active outbound network connections per process."""
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status != "ESTABLISHED" or not conn.raddr:
                continue
            try:
                proc = psutil.Process(conn.pid) if conn.pid else None
                record = {
                    "event_id": str(uuid.uuid4()),
                    "source": "host_agent",
                    "event_type": "network_conn",
                    "timestamp": _now_iso(),
                    "hostname": _hostname(),
                    "pid": conn.pid,
                    "process_name": proc.name() if proc else "unknown",
                    "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "remote_ip": conn.raddr.ip,
                    "remote_port": conn.raddr.port,
                    "protocol": "TCP" if conn.type == 1 else "UDP",
                }
                producer.send(KAFKA_TOPIC_RAW, value=record)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
    except psutil.AccessDenied:
        log.warning("Cannot read connections — run as root for full visibility")


def start_host_agent():
    producer = _make_producer()
    log.info("Host agent started")

    # File system watcher
    observer = Observer()
    handler = FileWriteHandler(producer)
    for watch_dir in WATCH_DIRS:
        if Path(watch_dir).exists():
            observer.schedule(handler, watch_dir, recursive=True)
            log.info(f"Watching: {watch_dir}")
    observer.start()

    # Process + connection polling loop
    _seen_pids.update(psutil.pids())   # seed with existing processes
    try:
        while True:
            _poll_processes(producer)
            _poll_connections(producer)
            time.sleep(PROCESS_POLL_INTERVAL)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    start_host_agent()