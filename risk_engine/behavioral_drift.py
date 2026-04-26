baseline = {}


def calculate_drift(source_ip, packet_count):
    if source_ip not in baseline:
        baseline[source_ip] = packet_count
        return 0

    old = baseline[source_ip]
    drift = abs(packet_count - old)

    # update baseline slowly
    baseline[source_ip] = (old + packet_count) / 2

    return drift