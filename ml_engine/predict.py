import joblib
import pandas as pd


MODEL_PATH = (
    "ml_engine/models/runtime_random_forest.pkl"
)

print("\nLoading Runtime ML Model...\n")

model = joblib.load(MODEL_PATH)

print("Runtime ML Model Loaded.\n")


ATTACK_LABELS = {

    0: "Benign",

    1: "DDoS",

    2: "Brute Force",

    3: "SQL Injection",

    4: "XSS"
}


def predict_attack(flow_data):

    try:

        input_data = {

            "protocol":
                flow_data.get("protocol", 0),

            "flow_duration":
                flow_data.get(
                    "flow_duration",
                    0
                ),

            "flow_packets_per_second":
                flow_data.get(
                    "flow_packets_per_second",
                    0
                ),

            "avg_packet_size":
                flow_data.get(
                    "avg_packet_size",
                    0
                ),

            "syn_count":
                flow_data.get(
                    "syn_count",
                    0
                ),

            "ack_count":
                flow_data.get(
                    "ack_count",
                    0
                ),

            "rst_count":
                flow_data.get(
                    "rst_count",
                    0
                ),

            "fin_count":
                flow_data.get(
                    "fin_count",
                    0
                ),

            "packet_count":
                flow_data.get(
                    "packet_count",
                    0
                )
        }

        input_df = pd.DataFrame(
            [input_data]
        )

        prediction = model.predict(
            input_df
        )[0]

        attack_name = ATTACK_LABELS.get(
            prediction,
            "Unknown"
        )

        return {

            "prediction":
                int(prediction),

            "attack_type":
                attack_name
        }

    except Exception as e:

        print(
            "ML Prediction Error:",
            e
        )

        return {

            "prediction": -1,

            "attack_type": "Error"
        }