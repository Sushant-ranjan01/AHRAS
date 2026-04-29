import os
import time
import re


class IPBlocker:

    def __init__(self):
        self.blocked_ips = set()
        self.block_history = []
        self.block_timestamps = {}

        # auto-unblock after 120 sec
        self.block_duration = 120

    def is_valid_ip(self, ip):
        if not isinstance(ip, str):
            return False

        pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
        return re.match(pattern, ip) is not None

    def is_private_ip(self, ip):
        return ip.startswith(("127.", "10.", "192.168"))

    def block_ip(self, ip):

        if not self.is_valid_ip(ip):
            return "Invalid IP"

        if self.is_private_ip(ip):
            return "Skipped (Local/Private IP)"

        if ip in self.blocked_ips:
            return "Already Blocked"

        try:
            command = f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}'
            result = os.system(command)

            if result != 0:
                return "Firewall command failed"

            self.blocked_ips.add(ip)
            self.block_history.append(ip)
            self.block_timestamps[ip] = time.time()

            return f"Blocked IP: {ip}"

        except Exception as e:
            return f"Error blocking IP: {e}"

    def unblock_expired_ips(self):

        current_time = time.time()
        to_remove = []

        for ip, ts in self.block_timestamps.items():
            if current_time - ts > self.block_duration:
                try:
                    command = f'netsh advfirewall firewall delete rule name="Block_{ip}"'
                    os.system(command)
                    to_remove.append(ip)
                except:
                    pass

        for ip in to_remove:
            self.blocked_ips.discard(ip)
            self.block_timestamps.pop(ip, None)

    def get_status(self):

        self.unblock_expired_ips()

        return {
            "total_blocked": len(self.blocked_ips),
            "recent_blocks": self.block_history[-10:]
        }