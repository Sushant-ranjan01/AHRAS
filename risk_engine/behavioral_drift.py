baseline = {}


def safe(value):
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return value
    try:
        return float(value)
    except:
        return 0


def calculate_drift(source_ip, packet_count):

    packet_count = safe(packet_count)

    if not isinstance(source_ip, str) or not source_ip:
        return 0

    if source_ip not in baseline:
        baseline[source_ip] = packet_count
        return 0

    old = safe(baseline.get(source_ip))

    drift = abs(packet_count - old)

    # 🔥 safe update
    baseline[source_ip] = (old + packet_count) / 2

    return drift