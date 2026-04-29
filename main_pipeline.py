from sensors.packet_sniffer import start_sniffing
from event_management.mongodb_client import MongoDBClient


def start_ahras():

    print("\nAHRAS Security Platform Started...\n")

    # Test DB connection
    db = MongoDBClient()

    print("No IPs blocked yet.\n")

    # Start packet capture
    start_sniffing()


if __name__ == "__main__":
    start_ahras()