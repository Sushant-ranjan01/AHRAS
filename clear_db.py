from event_management.mongodb_client import MongoDBClient


def main():
    db = MongoDBClient()

    if db.collection is None:
        print("Database not available. Cannot clear.")
        return

    before = db.count_events()
    print(f"Records before clearing: {before}")

    print("Clearing database...")
    db.clear_events()

    after = db.count_events()
    print(f"Records after clearing: {after}")

    if after == 0:
        print("Database cleared successfully.")
    else:
        print("Something went wrong. Data still exists.")


if __name__ == "__main__":
    main()