from collections import defaultdict
from datetime import datetime

traffic_window = defaultdict(list)

WINDOW_SIZE = 60  # seconds


def calculate_density(source_ip):
    now = datetime.now().timestamp()

    traffic_window[source_ip].append(now)

    # Remove old timestamps
    traffic_window[source_ip] = [
        t for t in traffic_window[source_ip]
        if now - t <= WINDOW_SIZE
    ]

    return len(traffic_window[source_ip])