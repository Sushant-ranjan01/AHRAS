from pymongo import MongoClient
from config.settings import MONGO_URI, MONGO_DB

_client = None

def get_db():
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI)
    return _client[MONGO_DB]

def get_events():
    return get_db()["events"]

def get_alerts():
    return get_db()["alerts"]