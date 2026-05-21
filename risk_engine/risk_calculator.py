import time

from collections import defaultdict

from detection.trust_engine import calculate_trust_score


class RiskEngine:

    def __init__(self):

        # -------------------------
        # WEIGHTS
        # -------------------------

        self.alpha = 0.4

        self.beta = 0.3

        self.gamma = 0.2

        self.delta = 0.1

        # -------------------------
        # MEMORY
        # -------------------------

        self.attack_history = defaultdict(list)

        self.packet_history = defaultdict(list)

        self.packet_timestamps = defaultdict(list)

        self.window_size = 30

        self.max_history = 20

    # -------------------------
    # SAFE NUMBER
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

    # -------------------------
    # NORMALIZATION
    # -------------------------

    def normalize(self, value, max_value):

        value = self.safe_num(value)

        return min(
            value / max_value,
            1
        ) if max_value else 0

    # -------------------------
    # PACKET RATE
    # -------------------------

    def calculate_packet_rate(self, src_ip):

        current_time = time.time()

        self.packet_timestamps[src_ip].append(
            current_time
        )

        # KEEP RECENT PACKETS ONLY

        self.packet_timestamps[src_ip] = [

            t

            for t in self.packet_timestamps[src_ip]

            if current_time - t <= self.window_size
        ]

        rate = len(
            self.packet_timestamps[src_ip]
        )

        rate = self.safe_num(rate)

        print(
            f"[DEBUG] {src_ip} → packet_rate: {rate}"
        )

        return rate

    # -------------------------
    # TEMPORAL ATTACK DENSITY
    # -------------------------

    def calculate_temporal_attack_density(
        self,
        src_ip
    ):

        current_time = time.time()

        self.attack_history[src_ip] = [

            t

            for t in self.attack_history[src_ip]

            if current_time - t <= 60
        ]

        density = len(
            self.attack_history[src_ip]
        )

        return self.safe_num(density)

    # -------------------------
    # BEHAVIORAL DRIFT
    # -------------------------

    def calculate_behavioral_drift(

        self,

        src_ip,

        packet_count
    ):

        packet_count = self.safe_num(
            packet_count
        )

        history = self.packet_history[src_ip]

        history.append(packet_count)

        if len(history) > self.max_history:

            history.pop(0)

        if len(history) < 5:

            return 0

        avg = (

            sum(history[:-1])

            / (len(history) - 1)
        )

        drift = abs(
            packet_count - avg
        )

        return self.safe_num(drift)

    # -------------------------
    # MAIN RISK FUNCTION
    # -------------------------

    def calculate_risk(

        self,

        hybrid_result,

        features
    ):

        src_ip = (
            features.get("src_ip")
            or "unknown"
        )

        packet_count = self.safe_num(

            features.get("packet_count")
        )

        packet_rate = self.calculate_packet_rate(
            src_ip
        )

        signature_score = self.safe_num(

            hybrid_result.get(
                "signature_score"
            )
        )

        anomaly_flag = bool(

            hybrid_result.get(
                "anomaly_detected"
            )
        )

        anomaly_score = (
            1 if anomaly_flag else 0
        )

        self.attack_history[src_ip].append(
            time.time()
        )

        tad = self.calculate_temporal_attack_density(
            src_ip
        )

        bd = self.calculate_behavioral_drift(

            src_ip,

            packet_count
        )

        # -------------------------
        # NORMALIZED SIGNALS
        # -------------------------

        S = self.normalize(
            signature_score,
            100
        )

        A = anomaly_score

        T = self.normalize(
            tad,
            50
        )

        B = self.normalize(
            bd,
            500
        )

        R = self.normalize(
            packet_rate,
            30
        )

        # -------------------------
        # BASE RISK
        # -------------------------

        risk_score = (

            self.alpha * S +

            self.beta * A +

            self.gamma * T +

            self.delta * (B + R)

        ) * 100

        # -------------------------
        # SIGNAL STRENGTH
        # -------------------------

        signal_strength = 0

        if signature_score > 20:
            signal_strength += 1

        if anomaly_flag:
            signal_strength += 1

        if tad > 10:
            signal_strength += 1

        if bd > 20:
            signal_strength += 1

        if packet_rate > 5:
            signal_strength += 1

        # -------------------------
        # BOOST STRONG SIGNALS
        # -------------------------

        if signal_strength >= 4:

            risk_score *= 1.5

        elif signal_strength >= 3:

            risk_score *= 1.2

        # -------------------------
        # TRUST ENGINE
        # -------------------------

        try:

            result = calculate_trust_score(
                src_ip
            )

            if (

                not result

                or not isinstance(
                    result,
                    (list, tuple)
                )

                or len(result) != 2
            ):

                trust_score = 0

                domain = "unknown"

            else:

                trust_score, domain = result

        except Exception:

            trust_score = 0

            domain = "unknown"

        trust_score = self.safe_num(
            trust_score
        )

        # TRUST REDUCTION

        if (

            trust_score > 0.7

            and signal_strength < 3
        ):

            risk_score *= 0.5

        # -------------------------
        # EXTRA BEHAVIORAL BOOSTS
        # -------------------------

        unique_ports = self.safe_num(

            features.get(
                "unique_ports"
            )
        )

        syn_count = self.safe_num(

            features.get(
                "syn_count"
            )
        )

        if unique_ports > 10:

            risk_score += 30

        if unique_ports > 30:

            risk_score += 50

        if syn_count > 50:

            risk_score += 40

        if packet_rate > 20:

            risk_score += 30

        # -------------------------
        # FINAL CLAMP
        # -------------------------

        risk_score = min(

            self.safe_num(risk_score),

            100
        )

        threat_level = self.get_threat_level(
            risk_score
        )

        # -------------------------
        # RESPONSE
        # -------------------------

        if risk_score >= 90:

            response_action = (

                f"Would Block "
                f"(Simulation): {src_ip}"
            )

        elif risk_score >= 50:

            response_action = (
                "Aggressive Monitoring"
            )

        else:

            response_action = "Monitored"

        return {

            "source_ip":
                src_ip,

            "domain":
                domain,

            "risk_score":
                round(risk_score, 2),

            "threat_level":
                threat_level,

            "temporal_attack_density":
                tad,

            "behavioral_drift":
                bd,

            "packet_rate":
                packet_rate,

            "trust_score":
                trust_score,

            "response_action":
                response_action
        }

    # -------------------------
    # THREAT LEVELS
    # -------------------------

    def get_threat_level(self, score):

        score = self.safe_num(score)

        if score >= 85:

            return "CRITICAL"

        elif score >= 50:

            return "HIGH"

        elif score >= 20:

            return "MEDIUM"

        else:

            return "LOW"