"""
Generates a synthetic, CICIDS2017-schema labeled dataset for evaluating
AHRAS's risk engine end-to-end, since the real public datasets
(CICIDS2017/NSL-KDD/UNSW-NB15) live on domains outside this sandbox's
network allowlist and are multi-GB anyway.

Design goal: realistic separation between benign and attack classes on
the SAME features AHRAS's detection mapping (_feature_to_detection in
evaluation/runner.py) actually reads — Total Fwd/Backward Packets,
Flow Bytes/s, Flow Packets/s, SYN Flag Count, Packet Length Std,
Destination Port — with per-attack-type signatures, plus injected label
noise so it isn't a trivially separable toy problem.
"""
import csv
import os
import random

random.seed(42)

# BUG FIX: this used to be a hardcoded absolute path
# ("/home/claude/synthetic_data/...") that only existed in the sandbox this
# script was first authored in. On any other machine it either wrote the
# dataset somewhere run_synthetic_evaluation.py never looks (silently
# "succeeding" while leaving evaluation/synthetic_data/ stale) or crashed
# outright with FileNotFoundError since that directory doesn't exist.
# Always write next to this script instead, so generate -> evaluate works
# out of the box regardless of where the repo is checked out.
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "synthetic_data")
OUTPUT_PATH = os.path.join(OUTPUT_DIR, "synthetic_cicids_style.csv")

HEADER = ["Flow Duration","Total Fwd Packets","Total Backward Packets",
          "Flow Bytes/s","Flow Packets/s","SYN Flag Count","ACK Flag Count",
          "Average Packet Size","Packet Length Std","Destination Port",
          "Source IP","Label"]

def rand_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def rand_attack_ip():
    return rand_ip()

def benign_row():
    return {
        "Flow Duration": random.uniform(50_000, 3_000_000),
        "Total Fwd Packets": random.randint(2, 40),
        "Total Backward Packets": random.randint(2, 40),
        "Flow Bytes/s": random.uniform(200, 8_000),
        "Flow Packets/s": random.uniform(1, 40),
        "SYN Flag Count": random.randint(0, 2),
        "ACK Flag Count": random.randint(1, 30),
        "Average Packet Size": random.uniform(200, 900),
        "Packet Length Std": random.uniform(20, 300),
        "Destination Port": random.choice([80, 443, 443, 443, 22, 53, 8080]),
        "Source IP": rand_ip(),
        "Label": "BENIGN",
    }

def dos_row():
    return {
        "Flow Duration": random.uniform(500, 20_000),
        "Total Fwd Packets": random.randint(500, 20_000),
        "Total Backward Packets": random.randint(0, 20),
        "Flow Bytes/s": random.uniform(500_000, 9_000_000),
        "Flow Packets/s": random.uniform(800, 50_000),
        "SYN Flag Count": random.randint(200, 20_000),
        "ACK Flag Count": random.randint(0, 5),
        "Average Packet Size": random.uniform(40, 120),
        "Packet Length Std": random.uniform(1000, 4000),
        "Destination Port": random.choice([80, 443]),
        "Source IP": rand_attack_ip(),
        "Label": random.choice(["DoS Hulk", "DDoS", "DoS GoldenEye"]),
    }

def portscan_row():
    return {
        "Flow Duration": random.uniform(10, 3_000),
        "Total Fwd Packets": random.randint(1, 4),
        "Total Backward Packets": random.randint(0, 2),
        "Flow Bytes/s": random.uniform(50, 3_000),
        "Flow Packets/s": random.uniform(100, 5_000),
        "SYN Flag Count": random.randint(1, 3),
        "ACK Flag Count": random.randint(0, 1),
        "Average Packet Size": random.uniform(40, 80),
        "Packet Length Std": random.uniform(1500, 5000),
        "Destination Port": random.randint(1, 65535),
        "Source IP": rand_attack_ip(),
        "Label": "PortScan",
    }

def bruteforce_row():
    return {
        "Flow Duration": random.uniform(1_000, 50_000),
        "Total Fwd Packets": random.randint(5, 30),
        "Total Backward Packets": random.randint(5, 30),
        "Flow Bytes/s": random.uniform(300, 4_000),
        "Flow Packets/s": random.uniform(50, 400),
        "SYN Flag Count": random.randint(1, 10),
        "ACK Flag Count": random.randint(5, 25),
        "Average Packet Size": random.uniform(60, 200),
        "Packet Length Std": random.uniform(900, 2500),
        "Destination Port": random.choice([22, 21]),
        "Source IP": rand_attack_ip(),
        "Label": random.choice(["SSH-Patator", "FTP-Patator"]),
    }

def webattack_row():
    return {
        "Flow Duration": random.uniform(2_000, 100_000),
        "Total Fwd Packets": random.randint(3, 60),
        "Total Backward Packets": random.randint(3, 60),
        "Flow Bytes/s": random.uniform(1_000, 20_000),
        "Flow Packets/s": random.uniform(10, 300),
        "SYN Flag Count": random.randint(0, 4),
        "ACK Flag Count": random.randint(2, 40),
        "Average Packet Size": random.uniform(300, 1400),
        "Packet Length Std": random.uniform(1200, 3500),
        "Destination Port": 443,
        "Source IP": rand_attack_ip(),
        "Label": random.choice(["Web Attack – SQL Injection", "Web Attack – XSS"]),
    }

def botnet_row():
    return {
        "Flow Duration": random.uniform(200_000, 5_000_000),
        "Total Fwd Packets": random.randint(4, 15),
        "Total Backward Packets": random.randint(4, 15),
        "Flow Bytes/s": random.uniform(100, 1_500),
        "Flow Packets/s": random.uniform(0.5, 8),
        "SYN Flag Count": random.randint(0, 2),
        "ACK Flag Count": random.randint(2, 10),
        "Average Packet Size": random.uniform(80, 300),
        "Packet Length Std": random.uniform(600, 1800),
        "Destination Port": random.choice([443, 8443, 6667]),
        "Source IP": rand_attack_ip(),
        "Label": "Bot",
    }

def make_dataset(n_total=6000, attack_frac=0.30, noise_frac=0.04):
    n_attack = int(n_total * attack_frac)
    n_benign = n_total - n_attack
    generators = [dos_row, portscan_row, bruteforce_row, webattack_row, botnet_row]

    rows = [benign_row() for _ in range(n_benign)]
    for _ in range(n_attack):
        rows.append(random.choice(generators)())

    random.shuffle(rows)

    # Inject label noise: flip a small fraction of labels to simulate
    # real-world imperfect ground truth / borderline flows, so this isn't
    # a trivially separable synthetic toy.
    n_noise = int(len(rows) * noise_frac)
    noise_idx = random.sample(range(len(rows)), n_noise)
    for i in noise_idx:
        if rows[i]["Label"] == "BENIGN":
            rows[i] = {**dos_row(), "Label": "BENIGN"}   # attack-like features, benign label
        else:
            rows[i] = {**benign_row(), "Label": rows[i]["Label"]}  # benign features, attack label

    return rows

if __name__ == "__main__":
    rows = make_dataset()
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(OUTPUT_PATH, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=HEADER)
        writer.writeheader()
        writer.writerows(rows)
    n_attack = sum(1 for r in rows if r["Label"] != "BENIGN")
    print(f"Wrote {len(rows)} rows ({n_attack} attack / {len(rows)-n_attack} benign) to {OUTPUT_PATH}")
