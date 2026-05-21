class SignatureDetector:

    def __init__(self):

        self.port_scan_threshold = 5

        self.syn_scan_threshold = 10

        self.packet_rate_threshold = 25

        self.packet_count_threshold = 200

    def safe(self, value):

        if value is None:
            return 0

        if isinstance(value, (int, float)):
            return value

        try:
            return int(value)

        except:
            return 0

    def detect(self, features):

        alerts = []

        severity_score = 0

        src_ip = features.get(
            "source_ip",
            "unknown"
        )

        protocol = self.safe(
            features.get("protocol")
        )

        dst_port = self.safe(
            features.get("dst_port")
        )

        unique_ports = self.safe(
            features.get("unique_ports")
        )

        packet_rate = self.safe(
            features.get("packet_rate")
        )

        packet_count = self.safe(
            features.get("packet_count")
        )

        syn_count = self.safe(
            features.get("syn_count")
        )

        ack_count = self.safe(
            features.get("ack_count")
        )

        print("\n====== SIGNATURE DEBUG ======")

        print("IP:", src_ip)

        print("Ports:", unique_ports)

        print("Packet Rate:", packet_rate)

        print("Packets:", packet_count)

        print("SYN:", syn_count)

        print("ACK:", ack_count)

        print("=============================\n")

        # IGNORE DNS

        if protocol == 17 and dst_port == 53:

            return {

                "alerts": [],

                "signature_score": 0
            }

        # PORT SCAN

        if (

            unique_ports >=
            self.port_scan_threshold

            and syn_count >=
            self.syn_scan_threshold
        ):

            alerts.append({

                "type": "PORT_SCAN",

                "source_ip": src_ip,

                "description":
                    "Nmap-style scan detected"
            })

            severity_score += 70

        # SYN SCAN

        if (

            syn_count >
            (ack_count * 2)

            and syn_count > 10
        ):

            alerts.append({

                "type": "SYN_SCAN",

                "source_ip": src_ip,

                "description":
                    "Suspicious SYN-heavy traffic"
            })

            severity_score += 50

        # HIGH PORT DIVERSITY

        if unique_ports > 15:

            alerts.append({

                "type":
                    "HIGH_PORT_DIVERSITY",

                "source_ip": src_ip,

                "description":
                    "Many destination ports"
            })

            severity_score += 50

        # PACKET BURST

        if packet_rate > 25:

            alerts.append({

                "type":
                    "PACKET_BURST",

                "source_ip": src_ip,

                "description":
                    "Burst traffic detected"
            })

            severity_score += 30

        # TRAFFIC FLOOD

        if packet_count > 200:

            alerts.append({

                "type":
                    "TRAFFIC_FLOOD",

                "source_ip": src_ip,

                "description":
                    "Very high traffic volume"
            })

            severity_score += 40

        return {

            "alerts": alerts,

            "signature_score":
                severity_score
        }