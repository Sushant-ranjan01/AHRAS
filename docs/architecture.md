# AHRAS Architecture

AHRAS (Adaptive Hybrid Risk Analysis System) is a real-time cybersecurity monitoring system.

## Pipeline

1. Packet Capture (Scapy)
2. Flow Generation
3. Signature Detection
4. Anomaly Detection
5. Hybrid Detection Engine
6. Risk Engine
7. Event Storage (MongoDB)
8. Dashboard Visualization

## Key Features

- Real-time packet monitoring
- Hybrid detection (rule-based + anomaly)
- Risk scoring with multi-factor analysis
- Trust-aware filtering
- Time-based attack detection