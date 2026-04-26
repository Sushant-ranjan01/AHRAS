import time


class AlertSystem:

    def __init__(self):
        self.last_alert_time = {}

    def generate_alert(self, event):

        ip = event.get("source_ip")
        threat = event.get("threat_level")
        risk = event.get("risk_score")

        current_time = time.time()

        # Prevent alert spam (cooldown 30 sec)
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