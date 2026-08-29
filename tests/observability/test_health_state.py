from observability.health import register_worker, heartbeat, snapshot

def test_worker_heartbeat():
    register_worker("test-worker")
    heartbeat("test-worker")
    state = snapshot()["test-worker"]
    assert state["healthy"] is True
