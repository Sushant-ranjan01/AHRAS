from collections import defaultdict
from datetime import datetime

traffic_window = defaultdict(list)

WINDOW_SIZE = 60  # seconds


def calculate_density(source_ip):

    # 🔥 input safety
    if not isinstance(source_ip, str) or not source_ip:
        return 0

    now = datetime.now().timestamp()

    traffic_window[source_ip].append(now)

    # keep only recent timestamps
    traffic_window[source_ip] = [
        t for t in traffic_window[source_ip]
        if now - t <= WINDOW_SIZE
    ]

    density = len(traffic_window[source_ip])

    # 🔥 cleanup empty keys
    if not traffic_window[source_ip]:
        del traffic_window[source_ip]

    return density