from collections import Counter
from datetime import datetime


class AttackTrends:

    def __init__(self, mongo_client):
        self.mongo_client = mongo_client

    def is_private_ip(self, ip):
        return isinstance(ip, str) and (
            ip.startswith("10.") or
            ip.startswith("192.168") or
            ip.startswith("127.")
        )

    def analyze(self):

        events = self.mongo_client.get_all_events()

        if not events:
            return {}

        ip_counter = Counter()
        attack_type_counter = Counter()
        hourly_distribution = Counter()

        for event in events:

            ip = event.get("source_ip")
            threat = event.get("threat_level", "")

            if not ip or self.is_private_ip(ip):
                continue

            if threat not in ["HIGH", "CRITICAL"]:
                continue

            ip_counter[ip] += 1

            alerts = event.get("alerts", [])

            for alert in alerts:
                if isinstance(alert, dict):
                    attack_type_counter[alert.get("type", "unknown")] += 1

            timestamp = event.get("timestamp")

            if isinstance(timestamp, str):
                try:
                    hour = datetime.fromisoformat(timestamp).hour
                    hourly_distribution[hour] += 1
                except:
                    pass

        return {
            "unique_attackers": len(ip_counter),
            "top_attacker": ip_counter.most_common(1),
            "most_common_attack": attack_type_counter.most_common(1),
            "peak_attack_hour": hourly_distribution.most_common(1),
            "top_5_attackers": ip_counter.most_common(5)
        }