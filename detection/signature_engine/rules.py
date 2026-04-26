rules = [

    {
        "name": "Port Scan",
        "condition": lambda f: f.get("dst_port") in range(1, 1024) and f.get("packet_count", 0) > 20,
        "score": 40
    },

    {
        "name": "Possible DDoS",
        "condition": lambda f: f.get("packet_count", 0) > 100,
        "score": 60
    },

    {
        "name": "Suspicious UDP Flood",
        "condition": lambda f: f.get("protocol") == 17 and f.get("packet_count", 0) > 80,
        "score": 50
    },

    {
        "name": "SSH Brute Force",
        "condition": lambda f: f.get("dst_port") == 22 and f.get("packet_count", 0) > 15,
        "score": 45
    },

    {
        "name": "HTTP Flood",
        "condition": lambda f: f.get("dst_port") == 80 and f.get("packet_count", 0) > 60,
        "score": 50
    },

    {
        "name": "DNS Amplification",
        "condition": lambda f: f.get("dst_port") == 53 and f.get("packet_count", 0) > 70,
        "score": 55
    },

]