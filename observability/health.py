"""Runtime health state for workers and dependencies."""
import threading, time
from typing import Dict

_lock = threading.Lock()
_workers: Dict[str, dict] = {}


def register_worker(name: str):
    with _lock:
        _workers[name] = {"status": "starting", "last_heartbeat": time.time(), "errors": 0}


def heartbeat(name: str):
    with _lock:
        state = _workers.setdefault(name, {"status": "starting", "last_heartbeat": time.time(), "errors": 0})
        state.update(status="running", last_heartbeat=time.time())


def worker_error(name: str):
    with _lock:
        state = _workers.setdefault(name, {"status": "starting", "last_heartbeat": time.time(), "errors": 0})
        state.update(status="degraded", last_heartbeat=time.time(), errors=state.get("errors", 0) + 1)


def snapshot(max_age=30):
    now = time.time()
    with _lock:
        result = {}
        for name, state in _workers.items():
            age = now - state["last_heartbeat"]
            result[name] = {**state, "heartbeat_age_seconds": round(age, 2), "healthy": age <= max_age and state["status"] == "running"}
        return result
