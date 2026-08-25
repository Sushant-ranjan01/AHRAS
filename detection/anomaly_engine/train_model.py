"""AHRAS — ML Anomaly Model Trainer (Phase 5a)"""
import os, sys, logging, numpy as np, joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from feature_engineering import FEATURE_NAMES
from config import config
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ahras.train")

def _normal(n):
    rng = np.random.default_rng(42)
    d = {
        "packet_count":       rng.integers(1,50,n).astype(float)/500,
        "byte_count":         rng.integers(64,50000,n).astype(float)/750000,
        "unique_ports":       rng.integers(1,5,n).astype(float)/65535,
        "avg_packet_size":    rng.uniform(100,1000,n)/1500,
        "max_packet_size":    rng.uniform(200,1500,n)/1500,
        "min_packet_size":    rng.uniform(60,300,n)/1500,
        "packets_per_second": rng.uniform(0.1,50,n)/1000,
        "bytes_per_second":   rng.uniform(100,100000,n)/1500000,
        "duration":           rng.uniform(0.1,60,n)/300,
    }
    pr = rng.choice([0,1,2],n,p=[0.7,0.2,0.1])
    d["protocol_tcp"]=(pr==0).astype(float); d["protocol_udp"]=(pr==1).astype(float); d["protocol_icmp"]=(pr==2).astype(float)
    d["src_port_norm"]=rng.integers(1024,65535,n).astype(float)/65535
    d["dst_port_norm"]=rng.choice([80,443,53,22,8080],n).astype(float)/65535
    d["syn_flag_ratio"]=rng.uniform(0,0.3,n)
    d["has_high_dst_port"]=rng.choice([0.,1.],n,p=[0.7,0.3])
    d["is_known_service_port"]=rng.choice([0.,1.],n,p=[0.3,0.7])
    return np.column_stack([d[f] for f in FEATURE_NAMES])

def train(output_path=None, n_samples=None):
    output_path = output_path or config.MODEL_PATH
    n = n_samples or config.TRAIN_SAMPLES
    X = _normal(n)
    pipe = Pipeline([("scaler",StandardScaler()),
                     ("model",IsolationForest(n_estimators=200,contamination=config.CONTAMINATION,random_state=42,n_jobs=-1))])
    pipe.fit(X)
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    joblib.dump(pipe, output_path)
    logger.info(f"Model saved → {output_path}")
    return pipe

if __name__ == "__main__": train()
