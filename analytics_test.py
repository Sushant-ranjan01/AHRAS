from event_management.mongodb_client import MongoDBClient
from analytics.attack_trends import AttackTrends


mongo_client = MongoDBClient()
analyzer = AttackTrends(mongo_client)

result = analyzer.analyze()

print("\n=== ATTACK ANALYTICS ===")
print(result)