from pymongo import MongoClient


class MongoDBClient:

    def __init__(self, uri="mongodb://localhost:27017/", db_name="AHRAS_DB"):
        self.client = MongoClient(uri)
        self.db = self.client[db_name]
        self.collection = self.db["events"]

    # ✅ INSERT EVENT
    def insert_event(self, event):
        self.collection.insert_one(event)

    # ✅ GET ALL EVENTS
    def get_all_events(self):
        return list(self.collection.find())

    # ✅ CLEAR DATABASE
    def clear_events(self):
        result = self.collection.delete_many({})
        print(f"🧹 Deleted {result.deleted_count} records")

    # ✅ OPTIONAL: COUNT EVENTS
    def count_events(self):
        return self.collection.count_documents({})