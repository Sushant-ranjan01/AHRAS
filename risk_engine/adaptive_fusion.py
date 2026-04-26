def fuse_signals(base_risk, density, drift, anomaly_flag):
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
    if anomaly_flag:
        risk += 30

    return min(risk, 100)