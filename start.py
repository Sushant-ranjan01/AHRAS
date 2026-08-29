"""
AHRAS — Quick Start Script
Trains ML model if missing, then launches the SOC dashboard.
Run: python start.py
"""
import os, sys, subprocess
sys.path.insert(0, os.path.dirname(__file__))

def main():
    print("=" * 60)
    print("  AHRAS — Adaptive Hybrid Risk-Aware Security System v2.0")
    print("=" * 60)

    # Train model if missing
    model_path = os.path.join("models", "anomaly_model.pkl")
    if not os.path.exists(model_path):
        print("\n[*] Training anomaly detection model...")
        os.makedirs("models", exist_ok=True)
        from detection.anomaly_engine.train_model import train
        train(output_path=model_path)
        print("[+] Model trained and saved.")

    print("\n[*] Starting AHRAS SOC Dashboard...")
    print("[*] Dashboard → http://localhost:8000")
    print("[*] Default credentials:")
    print("      Master  → admin / Admin@12345!")
    print("      Analyst → analyst / Analyst@12345!")
    print("\nPress Ctrl+C to stop.\n")

    import uvicorn
    from config import config
    uvicorn.run("main:app", host=config.API_HOST, port=config.API_PORT,
                reload=False, log_level="info")

if __name__ == "__main__":
    main()
