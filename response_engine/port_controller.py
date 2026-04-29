import subprocess


class PortController:

    def is_valid_port(self, port):
        return isinstance(port, int) and 1 <= port <= 65535

    def block_port(self, port):

        if not self.is_valid_port(port):
            print("Invalid port")
            return

        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=BlockPort{port}",
                "dir=in",
                "action=block",
                "protocol=TCP",
                f"localport={port}"
            ]

            result = subprocess.run(cmd, capture_output=True)

            if result.returncode == 0:
                print(f"Blocked port {port}")
            else:
                print("Block failed:", result.stderr.decode())

        except Exception as e:
            print("Port block error:", e)

    def unblock_port(self, port):

        if not self.is_valid_port(port):
            print("Invalid port")
            return

        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name=BlockPort{port}"
            ]

            result = subprocess.run(cmd, capture_output=True)

            if result.returncode == 0:
                print(f"Unblocked port {port}")
            else:
                print("Unblock failed:", result.stderr.decode())

        except Exception as e:
            print("Port unblock error:", e)