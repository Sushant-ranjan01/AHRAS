import subprocess


class PortController:

    def block_port(self, port):

        try:
            cmd = f'netsh advfirewall firewall add rule name="BlockPort{port}" dir=in action=block protocol=TCP localport={port}'
            subprocess.run(cmd, shell=True)
            print(f"Blocked port {port}")
        except Exception as e:
            print("Port block error:", e)

    def unblock_port(self, port):

        try:
            cmd = f'netsh advfirewall firewall delete rule name="BlockPort{port}"'
            subprocess.run(cmd, shell=True)
            print(f"Unblocked port {port}")
        except Exception as e:
            print("Port unblock error:", e)