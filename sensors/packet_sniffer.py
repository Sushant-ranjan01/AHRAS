from scapy.all import sniff
from datetime import datetime


def process_packet(packet):
    try:
        packet_data = {}

        if packet.haslayer("IP"):

            packet_data["timestamp"] = str(datetime.now())
            packet_data["src_ip"] = packet["IP"].src
            packet_data["dst_ip"] = packet["IP"].dst
            packet_data["protocol"] = packet["IP"].proto
            packet_data["packet_length"] = len(packet)

            if packet.haslayer("TCP"):
                packet_data["src_port"] = packet["TCP"].sport
                packet_data["dst_port"] = packet["TCP"].dport
                packet_data["transport"] = "TCP"

            elif packet.haslayer("UDP"):
                packet_data["src_port"] = packet["UDP"].sport
                packet_data["dst_port"] = packet["UDP"].dport
                packet_data["transport"] = "UDP"

            else:
                packet_data["transport"] = "OTHER"

            print(packet_data)

            return packet_data

    except Exception as e:
        print("Packet processing error:", e)


def start_sniffing():

    print("AHRAS Packet Sniffer Started...\n")

    sniff(
        prn=process_packet,
        store=False
    )


if __name__ == "__main__":
    start_sniffing()