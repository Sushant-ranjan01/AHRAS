class SignatureDetector:

    def __init__(self):

        self.port_scan_threshold = 8

        self.packet_rate_threshold = 200

        self.packet_count_threshold = 300

        self.syn_flood_threshold = 100

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

        unique_ports = self.safe(
            features.get("unique_ports")
        )

        packet_rate = self.safe(
            features.get(
                "flow_packets_per_second"
            )
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

        protocol = self.safe(
            features.get("protocol")
        )

        # ------------------------------
        # PORT SCAN DETECTION
        # ------------------------------

        if (
            protocol == 6
            and unique_ports >= self.port_scan_threshold
        ):

            alerts.append({

                "type": "PORT_SCAN",

                "source_ip": src_ip,

                "description":
                    "Multiple ports scanned"
            })

            severity_score += 50

        # ------------------------------
        # SYN FLOOD DETECTION
        # ------------------------------

        if (

            syn_count > self.syn_flood_threshold

            and ack_count < (
                syn_count * 0.2
            )
        ):

            alerts.append({

                "type": "SYN_FLOOD",

                "source_ip": src_ip,

                "description":
                    "Large SYN flood behavior"
            })

            severity_score += 70

        # ------------------------------
        # TRAFFIC FLOOD
        # ------------------------------

        if (

            packet_rate > self.packet_rate_threshold

            and packet_count > 100
        ):

            alerts.append({

                "type": "TRAFFIC_FLOOD",

                "source_ip": src_ip,

                "description":
                    "High traffic burst detected"
            })

            severity_score += 40

        # ------------------------------
        # HIGH PACKET VOLUME
        # ------------------------------

        if packet_count > self.packet_count_threshold:

            alerts.append({

                "type": "HIGH_TRAFFIC_SOURCE",

                "source_ip": src_ip,

                "description":
                    "Large packet volume detected"
            })

            severity_score += 30

        return {

            "alerts": alerts,

            "signature_score": severity_score
        }