from event_management.mongodb_client import MongoDBClient

def main():
    db = MongoDBClient()

    print("⚠️ Clearing database...")

    db.clear_events()

    print("✅ Database cleared successfully!")


if __name__ == "__main__":
    main()