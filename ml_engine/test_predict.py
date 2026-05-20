from predict import predict_attack

sample_flow = {

    "Destination Port": 80,
    "Flow Duration": 1000,
    "Total Fwd Packets": 10,
    "Total Backward Packets": 5,
    "Total Length of Fwd Packets": 500,
    "Total Length of Bwd Packets": 200,
    "Flow Bytes/s": 1000,
    "Flow Packets/s": 50
}

result = predict_attack(sample_flow)

print("\nPrediction Result:\n")

print(result)