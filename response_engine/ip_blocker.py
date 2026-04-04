import os


class IPBlocker:

    def __init__(self):
        self.blocked_ips = set()
        self.block_history = []

    def block_ip(self, ip):

        # Skip local/private IPs
        if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168"):
            return "Skipped (Local/Private IP)"

        # Avoid duplicate blocking
        if ip in self.blocked_ips:
            return "Already Blocked"

        try:
            command = f'netsh advfirewall firewall add rule name="Block_{ip}" dir=in action=block remoteip={ip}'
            os.system(command)

            self.blocked_ips.add(ip)
            self.block_history.append(ip)

            return f"Blocked IP: {ip}"

        except Exception as e:
            return f"Error blocking IP: {e}"

    def get_status(self):

        return {
            "total_blocked": len(self.blocked_ips),
            "recent_blocks": self.block_history[-10:]
        }