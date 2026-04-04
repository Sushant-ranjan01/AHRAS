import time
from collections import defaultdict


class RiskEngine:

    def __init__(self):

        self.alpha = 0.4
        self.beta = 0.3
        self.gamma = 0.2
        self.delta = 0.1

        self.attack_history = defaultdict(list)
        self.packet_history = defaultdict(list)

    def normalize(self, value, max_value):
        return min(value / max_value, 1)

    def calculate_temporal_attack_density(self, src_ip):

        current_time = time.time()

        recent_events = [
            t for t in self.attack_history[src_ip]
            if current_time - t <= 60
        ]

        self.attack_history[src_ip] = recent_events

        return len(recent_events)

    def calculate_behavioral_drift(self, src_ip, packet_count):

        history = self.packet_history[src_ip]
        history.append(packet_count)

        if len(history) < 5:
            return 0

        avg = sum(history) / len(history)
        drift = abs(packet_count - avg)

        return drift

    def calculate_risk(self, hybrid_result, features):

        src_ip = features.get("src_ip")
        packet_count = features.get("packet_count")

        signature_score = hybrid_result.get("signature_score", 0)
        anomaly_flag = hybrid_result.get("anomaly_detected", False)

        anomaly_score = 1 if anomaly_flag else 0

        # update attack history
        self.attack_history[src_ip].append(time.time())

        tad = self.calculate_temporal_attack_density(src_ip)
        bd = self.calculate_behavioral_drift(src_ip, packet_count)

        # normalization
        S = self.normalize(signature_score, 100)
        A = anomaly_score
        T = self.normalize(tad, 100)
        B = self.normalize(bd, 100)

        risk_score = (
            self.alpha * S +
            self.beta * A +
            self.gamma * T +
            self.delta * B
        ) * 100

        threat_level = self.get_threat_level(risk_score)

        return {
            "source_ip": src_ip,
            "risk_score": round(risk_score, 2),
            "threat_level": threat_level,
            "temporal_attack_density": tad,
            "behavioral_drift": bd
        }

    def get_threat_level(self, score):

        if score >= 80:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        else:
            return "LOW"