# API Documentation

## GET /dashboard

Returns the SOC dashboard UI.

---

## Data Source

MongoDB Collection: events

Each event contains:

- source_ip
- destination_ip
- packet_count
- signature_score
- anomaly_detected
- risk_score
- threat_level
- packet_rate
- trust_score
- response_action

---

## Notes

- Dashboard auto-refreshes every 10 minutes
- Uses real-time aggregation