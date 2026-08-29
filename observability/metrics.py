"""Prometheus metrics with graceful fallback when prometheus_client is absent."""
try:
    from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
    REQUESTS = Counter("ahras_api_requests_total", "HTTP requests", ["method", "path", "status"])
    LATENCY = Histogram("ahras_api_request_latency_seconds", "HTTP request latency", ["method", "path"])
    LOGIN_FAILURES = Counter("ahras_login_failures_total", "Failed logins")
    EVENTS = Counter("ahras_events_total", "Events processed")
    ACTIVE_SESSIONS = Gauge("ahras_active_sessions", "Active sessions")
    WORKER_ERRORS = Counter("ahras_worker_errors_total", "Worker errors", ["worker"])
    WORKER_HEALTH = Gauge("ahras_worker_health", "Worker health (1 healthy, 0 unhealthy)", ["worker"])
    QUEUE_DEPTH = Gauge("ahras_queue_depth", "Internal queue depth", ["queue"])
    PROCESS_CPU = Gauge("ahras_process_cpu_percent", "AHRAS process CPU percent")
    PROCESS_MEMORY = Gauge("ahras_process_memory_bytes", "AHRAS process RSS memory bytes")
    MONGODB_UP = Gauge("ahras_mongodb_up", "MongoDB availability")
    ENABLED = True
except Exception:
    ENABLED = False
    CONTENT_TYPE_LATEST = "text/plain"
    def generate_latest(): return b"# prometheus_client not installed\n"
    class _Noop:
        def labels(self, *a, **k): return self
        def inc(self, *a, **k): pass
        def observe(self, *a, **k): pass
        def set(self, *a, **k): pass
    REQUESTS = LATENCY = LOGIN_FAILURES = EVENTS = ACTIVE_SESSIONS = WORKER_ERRORS = WORKER_HEALTH = QUEUE_DEPTH = PROCESS_CPU = PROCESS_MEMORY = MONGODB_UP = _Noop()
