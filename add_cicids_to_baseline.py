"""Import BENIGN CICIDS/CSE-CIC-IDS2018 rows into AHRAS anomaly baseline.

The vector conversion is shared with runtime feature semantics through
feature_engineering.cicids_row_to_raw_features(), preventing train/eval drift.
"""
from __future__ import annotations

import argparse
import logging
import os
import csv
import shutil
import time

import numpy as np

from feature_engineering import cicids_row_to_raw_features, raw_features_to_vector

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("ahras.cicids_baseline")

BASELINE_PATH = os.path.join("data", "baseline_normal.npy")
BENIGN = {"benign", "normal", "normal."}


def _process_file(path: str, limit_per_file: int | None, rng: np.random.Generator):
    # Reservoir-sample only BENIGN rows. This avoids a first-300 bias in files
    # where traffic type changes over the chronological day.
    reservoir = []
    seen = 0
    skipped_attack = skipped_bad = 0

    with open(path, "r", encoding="utf-8-sig", errors="ignore", newline="") as fh:
        reader = csv.DictReader(fh)
        if not reader.fieldnames or not any(str(h).strip().lower() == "label" for h in reader.fieldnames):
            logger.warning("%s: Label column missing", os.path.basename(path))
            return [], 0, 0

        for raw_row in reader:
            label_key = next((h for h in reader.fieldnames if str(h).strip().lower() == "label"), None)
            label = str(raw_row.get(label_key, "") or "").strip().lower()
            if label not in BENIGN:
                skipped_attack += 1
                continue

            try:
                vector = raw_features_to_vector(cicids_row_to_raw_features(raw_row))
            except (ValueError, TypeError, KeyError):
                skipped_bad += 1
                continue

            if limit_per_file is None or limit_per_file <= 0:
                reservoir.append(vector)
                continue

            if seen < limit_per_file:
                reservoir.append(vector)
            else:
                j = int(rng.integers(0, seen + 1))
                if j < limit_per_file:
                    reservoir[j] = vector
            seen += 1

    return reservoir, skipped_attack, skipped_bad


def run(data_dir: str, limit_per_file: int | None = None, reset: bool = False, seed: int = 42):
    os.makedirs("data", exist_ok=True)
    csv_files = sorted(
        os.path.join(data_dir, name)
        for name in os.listdir(data_dir)
        if name.lower().endswith(".csv")
    )
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")

    if reset and os.path.exists(BASELINE_PATH):
        backup = f"{BASELINE_PATH}.bak-{int(time.time())}"
        shutil.copy2(BASELINE_PATH, backup)
        os.remove(BASELINE_PATH)
        logger.info("Reset requested; backed up existing baseline to %s", backup)

    rng = np.random.default_rng(seed)
    new_vectors = []
    total_attack = 0
    total_bad = 0

    for path in csv_files:
        vectors, skipped_attack, skipped_bad = _process_file(path, limit_per_file, rng)
        new_vectors.extend(vectors)
        total_attack += skipped_attack
        total_bad += skipped_bad
        logger.info("%s: imported %d BENIGN vectors", os.path.basename(path), len(vectors))

    if not new_vectors:
        raise RuntimeError("No usable BENIGN rows were found")

    X_new = np.asarray(new_vectors, dtype=np.float32)
    if not np.all(np.isfinite(X_new)):
        raise RuntimeError("Generated baseline contains non-finite values")

    if os.path.exists(BASELINE_PATH):
        old = np.load(BASELINE_PATH)
        if old.ndim != 2 or old.shape[1] != X_new.shape[1]:
            raise RuntimeError(f"Existing baseline shape {old.shape} incompatible with new {X_new.shape}")
        X = np.vstack([old, X_new])
    else:
        X = X_new

    np.save(BASELINE_PATH, X)
    logger.info("Baseline saved: %s shape=%s", BASELINE_PATH, X.shape)
    logger.info("Skipped non-BENIGN rows=%d; skipped unusable rows=%d", total_attack, total_bad)
    return X


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--limit-per-file", type=int, default=None)
    parser.add_argument("--reset", action="store_true", help="Replace the existing baseline after making a backup")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    run(args.data_dir, args.limit_per_file, args.reset, args.seed)