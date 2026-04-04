from pymongo import MongoClient


class MongoDBClient:

    def __init__(self, uri="mongodb://localhost:27017/", db_name="AHRAS_DB"):

        self.client = MongoClient(uri)
        self.db = self.client[db_name]

        # collections
        self.events_collection = self.db["security_events"]

    def insert_event(self, event):

        try:
            result = self.events_collection.insert_one(event)
            return result.inserted_id

        except Exception as e:
            print("MongoDB insert error:", e)

    def get_all_events(self):

        try:
            events = list(self.events_collection.find({}, {"_id": 0}))
            return events

        except Exception as e:
            print("MongoDB fetch error:", e)
            return []

    def get_events_by_ip(self, ip):

        try:
            events = list(self.events_collection.find(
                {"source_ip": ip},
                {"_id": 0}
            ))
            return events

        except Exception as e:
            print("MongoDB query error:", e)
            return []