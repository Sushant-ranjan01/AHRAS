rules = [

    {
        "name": "Port Scan",
        "condition": lambda f: 1 <= (f.get("dst_port") or 0) <= 1023
        and (f.get("packet_count") or 0) > 20,
        "score": 40
    },

    {
        "name": "Possible DDoS",
        "condition": lambda f: (f.get("packet_count") or 0) > 100,
        "score": 60
    },

    {
        "name": "Suspicious UDP Flood",
        "condition": lambda f: (f.get("protocol") or 0) == 17
        and (f.get("packet_count") or 0) > 80,
        "score": 50
    },

    {
        "name": "SSH Brute Force",
        "condition": lambda f: (f.get("dst_port") or 0) == 22
        and (f.get("packet_count") or 0) > 15,
        "score": 45
    },

    {
        "name": "HTTP Flood",
        "condition": lambda f: (f.get("dst_port") or 0) == 80
        and (f.get("packet_count") or 0) > 60,
        "score": 50
    },

    {
        "name": "DNS Amplification",
        "condition": lambda f: (f.get("dst_port") or 0) == 53
        and (f.get("packet_count") or 0) > 70,
        "score": 55
    },

]