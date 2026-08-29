"""Small dependency-free sliding-window rate limiter for AHRAS APIs."""
import threading
import time
from collections import defaultdict, deque

class RateLimiter:
    def __init__(self, limit: int = 120, window_seconds: int = 60):
        self.limit = limit
        self.window = window_seconds
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] >= self.window:
                q.popleft()
            if len(q) >= self.limit:
                retry = max(1, int(self.window - (now - q[0])))
                return False, retry
            q.append(now)
            return True, 0

    def cleanup(self):
        now = time.monotonic()
        with self._lock:
            dead = [k for k, q in self._hits.items() if not q or now - q[-1] >= self.window]
            for k in dead:
                self._hits.pop(k, None)
