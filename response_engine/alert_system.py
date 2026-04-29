import time


class AlertSystem:

    def __init__(self):
        self.last_alert_time = {}

    def safe(self, value, default=0):
        if value is None:
            return default
        return value

    def generate_alert(self, event):

        if not isinstance(event, dict):
            return None

        ip = event.get("source_ip") or "unknown"
        threat = event.get("threat_level") or "LOW"
        risk = self.safe(event.get("risk_score"), 0)

        current_time = time.time()

        # 🔥 cooldown protection
        if ip in self.last_alert_time:
            if current_time - self.last_alert_time[ip] < 30:
                return None

        self.last_alert_time[ip] = current_time

        alert = {
            "alert_type": "SECURITY_ALERT",
            "source_ip": ip,
            "threat_level": threat,
            "risk_score": risk,
            "message": f"Threat detected from {ip} with risk {risk}"
        }

        print("🚨 ALERT:", alert)

        return alert