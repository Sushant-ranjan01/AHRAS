def safe(value):
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return value
    try:
        return float(value)
    except:
        return 0


def fuse_signals(base_risk, density, drift, anomaly_flag):

    base_risk = safe(base_risk)
    density = safe(density)
    drift = safe(drift)

    risk = base_risk

    # Temporal spike
    if density > 100:
        risk += 30
    elif density > 50:
        risk += 15

    # Behavioral drift
    if drift > 50:
        risk += 20
    elif drift > 20:
        risk += 10

    # ML anomaly
    if bool(anomaly_flag):
        risk += 30

    return min(risk, 100)