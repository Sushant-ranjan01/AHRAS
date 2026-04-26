import time
from collections import defaultdict
from detection.trust_engine import calculate_trust_score


class RiskEngine:

    def __init__(self):

        self.alpha = 0.4
        self.beta = 0.3
        self.gamma = 0.2
        self.delta = 0.1

        self.attack_history = defaultdict(list)
        self.packet_history = defaultdict(list)
        self.packet_timestamps = defaultdict(list)

        self.window_size = 30   # ✅ increased window
        self.max_history = 20

    def normalize(self, value, max_value):
        return min(value / max_value, 1)

    def calculate_packet_rate(self, src_ip):

        current_time = time.time()

        self.packet_timestamps[src_ip].append(current_time)

        # keep only last N seconds
        self.packet_timestamps[src_ip] = [
            t for t in self.packet_timestamps[src_ip]
            if current_time - t <= self.window_size
        ]

        rate = len(self.packet_timestamps[src_ip])

        # 🔍 DEBUG (you can remove later)
        print(f"[DEBUG] {src_ip} → packet_rate: {rate}")

        return rate

    def calculate_temporal_attack_density(self, src_ip):

        current_time = time.time()

        self.attack_history[src_ip] = [
            t for t in self.attack_history[src_ip]
            if current_time - t <= 60
        ]

        return len(self.attack_history[src_ip])

    def calculate_behavioral_drift(self, src_ip, packet_count):

        history = self.packet_history[src_ip]

        history.append(packet_count)

        if len(history) > self.max_history:
            history.pop(0)

        if len(history) < 5:
            return 0

        avg = sum(history[:-1]) / (len(history) - 1)
        drift = abs(packet_count - avg)

        return drift

    def calculate_risk(self, hybrid_result, features):

        src_ip = features.get("src_ip")
        packet_count = features.get("packet_count", 0)

        # 🚫 Ignore local traffic
        if src_ip.startswith(("192.", "10.", "172.")):
            return {
                "source_ip": src_ip,
                "domain": "local",
                "risk_score": 0,
                "threat_level": "LOW",
                "temporal_attack_density": 0,
                "behavioral_drift": 0,
                "packet_rate": 0,
                "trust_score": 1,
                "response_action": "Ignored (Local Traffic)"
            }

        # 🔥 Packet rate
        packet_rate = self.calculate_packet_rate(src_ip)

        # 🚫 Only ignore VERY low traffic (fixed)
        if packet_rate < 2:
            return {
                "source_ip": src_ip,
                "domain": "normal",
                "risk_score": 5,
                "threat_level": "LOW",
                "temporal_attack_density": 0,
                "behavioral_drift": 0,
                "packet_rate": packet_rate,
                "trust_score": 1,
                "response_action": "Monitored"
            }

        signature_score = hybrid_result.get("signature_score", 0)
        anomaly_flag = hybrid_result.get("anomaly_detected", False)

        anomaly_score = 1 if anomaly_flag else 0

        self.attack_history[src_ip].append(time.time())

        tad = self.calculate_temporal_attack_density(src_ip)
        bd = self.calculate_behavioral_drift(src_ip, packet_count)

        S = self.normalize(signature_score, 100)
        A = anomaly_score
        T = self.normalize(tad, 50)
        B = self.normalize(bd, 500)
        R = self.normalize(packet_rate, 50)

        risk_score = (
            self.alpha * S +
            self.beta * A +
            self.gamma * T +
            self.delta * (B + R)
        ) * 100

        # 🔥 Multi-signal validation
        signal_strength = 0

        if signature_score > 30:
            signal_strength += 1
        if anomaly_flag:
            signal_strength += 1
        if tad > 20:
            signal_strength += 1
        if bd > 50:
            signal_strength += 1
        if packet_rate > 10:
            signal_strength += 1

        if signal_strength <= 1:
            risk_score *= 0.4
        elif signal_strength == 2:
            risk_score *= 0.7

        # 🔥 Trust layer
        trust_score, domain = calculate_trust_score(src_ip)

        if trust_score > 0.5 and signal_strength < 3:
            risk_score *= 0.3

        threat_level = self.get_threat_level(risk_score)

        # 🔥 Simulation mode (NO REAL BLOCK)
        if risk_score >= 90 and signal_strength >= 3:
            response_action = f"Would Block (Simulation): {src_ip}"
        else:
            response_action = "Monitored"

        return {
            "source_ip": src_ip,
            "domain": domain,
            "risk_score": round(risk_score, 2),
            "threat_level": threat_level,
            "temporal_attack_density": tad,
            "behavioral_drift": bd,
            "packet_rate": packet_rate,
            "trust_score": trust_score,
            "response_action": response_action
        }

    def get_threat_level(self, score):

        if score >= 90:
            return "CRITICAL"
        elif score >= 75:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"