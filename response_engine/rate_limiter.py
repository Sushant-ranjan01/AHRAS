import time
from collections import defaultdict


class RateLimiter:

    def __init__(self):
        self.request_log = defaultdict(list)
        self.window = 10  # seconds
        self.threshold = 50

    def is_rate_limited(self, ip):

        current_time = time.time()

        self.request_log[ip].append(current_time)

        # keep only recent timestamps
        self.request_log[ip] = [
            t for t in self.request_log[ip]
            if current_time - t <= self.window
        ]

        if len(self.request_log[ip]) > self.threshold:
            print(f"Rate limit exceeded for {ip}")
            return True

        return False