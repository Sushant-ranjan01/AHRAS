from collections import defaultdict

import time


class FlowGenerator:

    def __init__(self):

        # --------------------------------
        # FLOW MEMORY
        # --------------------------------

        self.flows = defaultdict(

            lambda: {

                "packet_count": 0,

                "total_bytes": 0,

                "start_time": time.time(),

                "last_seen": time.time(),

                "forward_packets": 0,

                "backward_packets": 0,

                "syn_count": 0,

                "ack_count": 0,

                "rst_count": 0,

                "fin_count": 0
            }
        )

        # --------------------------------
        # SOURCE BEHAVIOR MEMORY
        # --------------------------------

        self.behavior_memory = defaultdict(

            lambda: {

                "packet_count": 0,

                "timestamps": [],

                "syn_count": 0,

                "ack_count": 0,

                "port_timestamps": {}
            }
        )

        self.timeout = 10

    # --------------------------------
    # SAFE INTEGER
    # --------------------------------

    def safe_int(self, value):

        if value is None:
            return 0

        if isinstance(value, (int, float)):
            return int(value)

        try:
            return int(value)

        except:
            return 0

    # --------------------------------
    # MAIN PACKET PROCESSOR
    # --------------------------------

    def process_packet(self, packet):

        try:

            if not isinstance(packet, dict):

                return None

            src_ip = packet.get(
                "src_ip"
            ) or "unknown"

            dst_ip = packet.get(
                "dst_ip"
            ) or "unknown"

            flow_key = (
                src_ip,
                dst_ip
            )

            flow = self.flows[flow_key]

            memory = self.behavior_memory[
                src_ip
            ]

            # --------------------------------
            # BASIC FLOW UPDATES
            # --------------------------------

            flow["packet_count"] += 1

            memory["packet_count"] += 1

            packet_length = self.safe_int(

                packet.get(
                    "packet_length"
                )
            )

            flow["total_bytes"] += (
                packet_length
            )

            src_port = self.safe_int(

                packet.get(
                    "src_port"
                )
            )

            dst_port = self.safe_int(

                packet.get(
                    "dst_port"
                )
            )

            protocol = self.safe_int(

                packet.get(
                    "protocol"
                )
            )

            flags = packet.get(
                "flags",
                ""
            )

            # --------------------------------
            # PORT BEHAVIOR TRACKING
            # --------------------------------

            current_time = time.time()

            if dst_port:

                memory["port_timestamps"][
                    dst_port
                ] = current_time

            # REMOVE OLD PORTS

            memory["port_timestamps"] = {

                port: ts

                for port, ts in

                memory[
                    "port_timestamps"
                ].items()

                if current_time - ts < 15
            }

            unique_ports = len(

                memory[
                    "port_timestamps"
                ]
            )

            # --------------------------------
            # SLIDING WINDOW
            # --------------------------------

            memory["timestamps"].append(
                current_time
            )

            memory["timestamps"] = [

                t

                for t in
                memory["timestamps"]

                if current_time - t < 10
            ]

            packet_rate = len(

                memory["timestamps"]
            )

            # --------------------------------
            # TCP FLAG TRACKING
            # --------------------------------

            if "S" in flags:

                flow["syn_count"] += 1

                memory["syn_count"] += 1

            if "A" in flags:

                flow["ack_count"] += 1

                memory["ack_count"] += 1

            if "R" in flags:

                flow["rst_count"] += 1

            if "F" in flags:

                flow["fin_count"] += 1

            # --------------------------------
            # FLOW TIMING
            # --------------------------------

            flow["forward_packets"] += 1

            flow["last_seen"] = current_time

            duration = (

                flow["last_seen"]

                - flow["start_time"]
            )

            if duration <= 0:

                duration = 1

            packets_per_second = (

                flow["packet_count"]

                / duration
            )

            avg_packet_size = (

                flow["total_bytes"]

                / flow["packet_count"]
            )

            # --------------------------------
            # DEBUG
            # --------------------------------

            print("\n========== FLOW DEBUG ==========")

            print("Source IP:", src_ip)

            print("Destination Port:", dst_port)

            print("Unique Ports:", unique_ports)

            print("Packet Rate:", packet_rate)

            print(
                "SYN Count:",
                memory["syn_count"]
            )

            print(
                "ACK Count:",
                memory["ack_count"]
            )

            print("================================\n")

            # --------------------------------
            # RETURN FEATURES
            # --------------------------------

            return {

                "source_ip":
                    src_ip,

                "destination_ip":
                    dst_ip,

                "packet_count":
                    memory[
                        "packet_count"
                    ],

                "protocol":
                    protocol,

                "src_port":
                    src_port,

                "dst_port":
                    dst_port,

                "unique_ports":
                    unique_ports,

                "flow_duration":
                    round(
                        duration,
                        2
                    ),

                "flow_packets_per_second":
                    round(
                        packets_per_second,
                        2
                    ),

                "packet_rate":
                    packet_rate,

                "total_bytes":
                    flow[
                        "total_bytes"
                    ],

                "avg_packet_size":
                    round(
                        avg_packet_size,
                        2
                    ),

                "syn_count":
                    memory[
                        "syn_count"
                    ],

                "ack_count":
                    memory[
                        "ack_count"
                    ],

                "rst_count":
                    flow[
                        "rst_count"
                    ],

                "fin_count":
                    flow[
                        "fin_count"
                    ],

                "forward_packets":
                    flow[
                        "forward_packets"
                    ]
            }

        except Exception as e:

            print(
                "Flow error:",
                e
            )

            return None

    # --------------------------------
    # CLEANUP
    # --------------------------------

    def cleanup_flows(self):

        current_time = time.time()

        expired = [

            key

            for key, flow in
            self.flows.items()

            if (

                current_time

                - flow["last_seen"]

                > self.timeout
            )
        ]

        for key in expired:

            del self.flows[key]