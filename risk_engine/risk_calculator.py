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

        self.window_size = 30
        self.max_history = 20

    # -------------------------
    # 🔥 SAFE NUMERIC HANDLING
    # -------------------------
    def safe_num(self, value):
        if value is None:
            return 0
        if isinstance(value, (int, float)):
            return value
        try:
            return float(value)
        except:
            return 0

    def normalize(self, value, max_value):
        value = self.safe_num(value)
        return min(value / max_value, 1) if max_value else 0

    # -------------------------
    # 🔥 PACKET RATE
    # -------------------------
    def calculate_packet_rate(self, src_ip):

        current_time = time.time()

        self.packet_timestamps[src_ip].append(current_time)

        # keep only recent timestamps
        self.packet_timestamps[src_ip] = [
            t for t in self.packet_timestamps[src_ip]
            if current_time - t <= self.window_size
        ]

        rate = len(self.packet_timestamps[src_ip])
        rate = self.safe_num(rate)

        print(f"[DEBUG] {src_ip} → packet_rate: {rate}")

        # 🔥 cleanup empty keys
        if not self.packet_timestamps[src_ip]:
            del self.packet_timestamps[src_ip]

        return rate

    # -------------------------
    # 🔥 TEMPORAL ATTACK DENSITY
    # -------------------------
    def calculate_temporal_attack_density(self, src_ip):

        current_time = time.time()

        self.attack_history[src_ip] = [
            t for t in self.attack_history[src_ip]
            if current_time - t <= 60
        ]

        density = len(self.attack_history[src_ip])

        # 🔥 cleanup empty keys
        if not self.attack_history[src_ip]:
            del self.attack_history[src_ip]

        return self.safe_num(density)

    # -------------------------
    # 🔥 BEHAVIORAL DRIFT
    # -------------------------
    def calculate_behavioral_drift(self, src_ip, packet_count):

        packet_count = self.safe_num(packet_count)

        history = self.packet_history[src_ip]
        history.append(packet_count)

        if len(history) > self.max_history:
            history.pop(0)

        if len(history) < 5:
            return 0

        avg = sum(history[:-1]) / (len(history) - 1)
        drift = abs(packet_count - avg)

        return self.safe_num(drift)

    # -------------------------
    # 🔥 MAIN RISK FUNCTION
    # -------------------------
    def calculate_risk(self, hybrid_result, features):

        src_ip = features.get("src_ip") or "unknown"
        packet_count = self.safe_num(features.get("packet_count"))

        # 🔥 Ignore local traffic
        if isinstance(src_ip, str) and src_ip.startswith(("192.", "10.", "172.")):
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

        packet_rate = self.calculate_packet_rate(src_ip)

        signature_score = self.safe_num(hybrid_result.get("signature_score"))
        anomaly_flag = bool(hybrid_result.get("anomaly_detected"))

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

        # -------------------------
        # 🔥 SIGNAL STRENGTH
        # -------------------------
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

        # -------------------------
        # 🔥 TRUST ENGINE SAFE
        # -------------------------
        try:
            result = calculate_trust_score(src_ip)

            if not result or not isinstance(result, (list, tuple)) or len(result) != 2:
                trust_score, domain = 0, "unknown"
            else:
                trust_score, domain = result

        except Exception:
            trust_score, domain = 0, "unknown"

        trust_score = self.safe_num(trust_score)

        if trust_score > 0.5 and signal_strength < 3:
            risk_score *= 0.3

        # 🔥 FINAL CLAMP
        risk_score = min(self.safe_num(risk_score), 100)

        threat_level = self.get_threat_level(risk_score)

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

    # -------------------------
    # 🔥 THREAT LEVEL
    # -------------------------
    def get_threat_level(self, score):

        score = self.safe_num(score)

        if score >= 90:
            return "CRITICAL"
        elif score >= 75:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"