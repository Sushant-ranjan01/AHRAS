from pymongo import MongoClient
from pymongo.errors import PyMongoError


class MongoDBClient:

    def __init__(self, uri="mongodb://localhost:27017/", db_name="AHRAS_DB"):

        try:
            self.client = MongoClient(uri, serverSelectionTimeoutMS=2000)
            self.client.server_info()  # force connection check

            self.db = self.client[db_name]
            self.collection = self.db["events"]

            print("MongoDB connected")

        except Exception as e:
            print("MongoDB connection failed:", e)
            self.client = None
            self.db = None
            self.collection = None

    # INSERT EVENT
    def insert_event(self, event):

        if self.collection is None:
            print("DB not available")
            return

        try:
            self.collection.insert_one(event)
        except Exception as e:
            print("Insert error:", e)

    # GET ALL EVENTS
    def get_all_events(self):

        if self.collection is None:
            return []

        try:
            return list(self.collection.find())
        except PyMongoError as e:
            print("Fetch error:", e)
            return []

    # CLEAR DATABASE
    def clear_events(self):

        if self.collection is None:
            print("DB not available.")
            return

        try:
            result = self.collection.delete_many({})
            print(f"Deleted {result.deleted_count} records")
        except PyMongoError as e:
            print("Delete error:", e)

    # COUNT EVENTS
    def count_events(self):

        if self.collection is None:
            return 0

        try:
            return self.collection.count_documents({})
        except PyMongoError as e:
            print("Count error:", e)
            return 0