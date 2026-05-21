import os
from dotenv import load_dotenv

load_dotenv()

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_TOPIC_RAW = "raw.telemetry"
KAFKA_TOPIC_NORMALIZED = "normalized.events"

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = "ahras"
MONGO_COLLECTION_EVENTS = "events"

NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE", "eth0")
FLOW_WINDOW_SECONDS = 10

GEO_API_URL = "http://ip-api.com/json/{ip}?fields=country,city,org,isp,lat,lon"
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")