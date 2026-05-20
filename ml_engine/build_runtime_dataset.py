import pandas as pd

INPUT = (
    "ml_engine/datasets/processed/final_features.csv"
)

OUTPUT = (
    "ml_engine/datasets/processed/runtime_features.csv"
)

print("\nLoading engineered dataset...\n")

df = pd.read_csv(INPUT)

print("Selecting runtime-compatible features...\n")

selected_features = [

    "Protocol",

    "Flow Duration",

    "Flow Packets/s",

    "Packet Length Mean",

    "SYN Flag Count",

    "ACK Flag Count",

    "RST Flag Count",

    "FIN Flag Count",

    "Total Fwd Packets",

    "Label"
]

runtime_df = df[selected_features]

runtime_df.columns = [

    "protocol",

    "flow_duration",

    "flow_packets_per_second",

    "avg_packet_size",

    "syn_count",

    "ack_count",

    "rst_count",

    "fin_count",

    "packet_count",

    "Label"
]

print(runtime_df.head())

print("\nDataset Shape:")

print(runtime_df.shape)

print("\nSaving runtime-compatible dataset...\n")

runtime_df.to_csv(
    OUTPUT,
    index=False
)

print("\nRuntime Dataset Ready.")