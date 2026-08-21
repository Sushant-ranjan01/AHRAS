"""
AHRAS — Add CICIDS / CSE-CIC-IDS2018 BENIGN Traffic to Anomaly Baseline
=========================================================================

WHAT THIS DOES
--------------
Extracts BENIGN-labelled flow records from CICIDS2017 or
CSE-CIC-IDS2018 CSV files, maps their dataset-specific column names
onto AHRAS's existing FEATURE_NAMES schema, normalises them using
AHRAS's existing _NORM ranges, and appends the resulting vectors to:

    data/baseline_normal.npy

The resulting baseline can then be used by:

    python retrain_baseline.py train

SUPPORTED DATASETS
------------------
1. CICIDS2017
2. CSE-CIC-IDS2018

The importer automatically supports both common column naming schemes.

IMPORTANT
---------
This script only adds BENIGN traffic to the anomaly-model baseline.

It does NOT train the model itself.

Recommended workflow:

    python add_cicids_to_baseline.py --data-dir data/cse_cic_ids2018 --limit-per-file 300

then:

    python retrain_baseline.py train

"""

import argparse
import csv
import glob
import logging
import math
import os
import sys

import numpy as np


# ---------------------------------------------------------------------------
# AHRAS imports
# ---------------------------------------------------------------------------

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from feature_engineering.feature_extractor import (
    FEATURE_NAMES,
    KNOWN_SVC,
    _NORM,
)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger("ahras.cicids_baseline")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASELINE_PATH = os.path.join("data", "baseline_normal.npy")

# Accepted representations of normal traffic.
_BENIGN_TOKENS = {
    "benign",
    "normal",
    "normal.",
}

# Protocol mappings.
_PROTO_MAP = {
    "1": "icmp",
    "6": "tcp",
    "17": "udp",
    "icmp": "icmp",
    "tcp": "tcp",
    "udp": "udp",
    "ICMP": "icmp",
    "TCP": "tcp",
    "UDP": "udp",
}


# ---------------------------------------------------------------------------
# Dataset column aliases
# ---------------------------------------------------------------------------
#
# The same AHRAS feature can have different names in CICIDS2017 and
# CSE-CIC-IDS2018.
#
# Example:
#
# CICIDS2017:
#     Total Fwd Packets
#
# CSE-CIC-IDS2018:
#     Tot Fwd Pkts
#
# This mapping lets the importer support both.
# ---------------------------------------------------------------------------

COLUMN_ALIASES = {

    "dst_port": [
        "Destination Port",
        "Dst Port",
    ],

    "src_port": [
        "Source Port",
        "Src Port",
    ],

    "protocol": [
        "Protocol",
    ],

    "flow_duration": [
        "Flow Duration",
    ],

    "fwd_packets": [
        "Total Fwd Packets",
        "Tot Fwd Pkts",
    ],

    "bwd_packets": [
        "Total Backward Packets",
        "Tot Bwd Pkts",
    ],

    "fwd_bytes": [
        "Total Length of Fwd Packets",
        "TotLen Fwd Pkts",
    ],

    "bwd_bytes": [
        "Total Length of Bwd Packets",
        "TotLen Bwd Pkts",
    ],

    "fwd_pkt_max": [
        "Fwd Packet Length Max",
        "Fwd Pkt Len Max",
    ],

    "bwd_pkt_max": [
        "Bwd Packet Length Max",
        "Bwd Pkt Len Max",
    ],

    "fwd_pkt_min": [
        "Fwd Packet Length Min",
        "Fwd Pkt Len Min",
    ],

    "bwd_pkt_min": [
        "Bwd Packet Length Min",
        "Bwd Pkt Len Min",
    ],

    "avg_packet_size": [
        "Average Packet Size",
        "Pkt Size Avg",
        "Pkt Len Mean",
    ],

    "flow_packets_per_second": [
        "Flow Packets/s",
    ],

    "flow_bytes_per_second": [
        "Flow Bytes/s",
    ],

    "syn_count": [
        "SYN Flag Count",
        "SYN Flag Cnt",
    ],

    "label": [
        "Label",
    ],
}


# ---------------------------------------------------------------------------
# Helper: normalize CSV headers
# ---------------------------------------------------------------------------

def _clean_header(value):
    """
    Clean a CSV header.

    Handles:
    - UTF-8 BOM
    - whitespace
    - accidental hidden characters
    """
    if value is None:
        return ""

    return (
        str(value)
        .replace("\ufeff", "")
        .strip()
    )


# ---------------------------------------------------------------------------
# Helper: normalize row keys
# ---------------------------------------------------------------------------

def _clean_row(row):
    """
    Clean all CSV dictionary keys.
    """
    cleaned = {}

    for key, value in row.items():
        clean_key = _clean_header(key)

        if clean_key:
            cleaned[clean_key] = value

    return cleaned


# ---------------------------------------------------------------------------
# Helper: find a column using aliases
# ---------------------------------------------------------------------------

def _get_raw(row, aliases, default=None):
    """
    Return the first available column value from the alias list.
    """

    for name in aliases:

        if name in row:
            value = row[name]

            if value is None:
                continue

            return value

    return default


# ---------------------------------------------------------------------------
# Helper: safe numeric conversion
# ---------------------------------------------------------------------------

def _safe_float(value, default=0.0):
    """
    Convert a value to a finite float.

    Handles:
    - empty strings
    - NaN
    - Infinity
    - invalid values
    """

    if value is None:
        return default

    try:
        text = str(value).strip()

        if not text:
            return default

        number = float(text)

        if not math.isfinite(number):
            return default

        return number

    except (ValueError, TypeError):
        return default


# ---------------------------------------------------------------------------
# Helper: get numeric dataset feature
# ---------------------------------------------------------------------------

def _get_float(row, aliases, default=0.0):
    """
    Get a numeric feature from a row using column aliases.
    """

    value = _get_raw(
        row,
        aliases,
        default=default,
    )

    return _safe_float(
        value,
        default=default,
    )


# ---------------------------------------------------------------------------
# AHRAS normalization
# ---------------------------------------------------------------------------

def _norm_feature(key, value):
    """
    Apply the same normalization ranges used by AHRAS.
    """

    value = _safe_float(value, 0.0)

    if key not in _NORM:
        return float(value)

    lo, hi = _NORM[key]

    if hi == lo:
        return 0.0

    normalized = (value - lo) / (hi - lo)

    # Keep normalized value within AHRAS's expected 0–1 range.
    return max(
        0.0,
        min(
            1.0,
            normalized,
        ),
    )


# ---------------------------------------------------------------------------
# Convert one dataset row into an AHRAS vector
# ---------------------------------------------------------------------------

def _row_to_vector(row):
    """
    Convert a CICIDS2017 / CSE-CIC-IDS2018 row into
    AHRAS FEATURE_NAMES format.

    Returns:
        numpy array if valid
        None if the flow is unusable
    """

    # -------------------------------------------------------
    # Basic flow counts
    # -------------------------------------------------------

    fwd_pkts = _get_float(
        row,
        COLUMN_ALIASES["fwd_packets"],
    )

    bwd_pkts = _get_float(
        row,
        COLUMN_ALIASES["bwd_packets"],
    )

    packet_count = fwd_pkts + bwd_pkts

    # A flow with zero packets is unusable.
    if packet_count <= 0:
        return None

    # -------------------------------------------------------
    # Bytes
    # -------------------------------------------------------

    fwd_bytes = _get_float(
        row,
        COLUMN_ALIASES["fwd_bytes"],
    )

    bwd_bytes = _get_float(
        row,
        COLUMN_ALIASES["bwd_bytes"],
    )

    byte_count = fwd_bytes + bwd_bytes

    # -------------------------------------------------------
    # Duration
    # -------------------------------------------------------
    #
    # Both CICIDS2017 and CSE-CIC-IDS2018 commonly represent
    # Flow Duration in microseconds.
    #
    # AHRAS uses seconds.
    # -------------------------------------------------------

    duration = (
        _get_float(
            row,
            COLUMN_ALIASES["flow_duration"],
        )
        / 1e6
    )

    # -------------------------------------------------------
    # Packets/sec and bytes/sec
    # -------------------------------------------------------

    pps = _get_float(
        row,
        COLUMN_ALIASES["flow_packets_per_second"],
    )

    bps = _get_float(
        row,
        COLUMN_ALIASES["flow_bytes_per_second"],
    )

    # -------------------------------------------------------
    # Packet size
    # -------------------------------------------------------

    avg_pkt = _get_float(
        row,
        COLUMN_ALIASES["avg_packet_size"],
    )

    # If average packet size is unavailable,
    # calculate it from bytes / packets.
    if avg_pkt <= 0:
        avg_pkt = byte_count / max(
            packet_count,
            1.0,
        )

    fwd_max = _get_float(
        row,
        COLUMN_ALIASES["fwd_pkt_max"],
    )

    bwd_max = _get_float(
        row,
        COLUMN_ALIASES["bwd_pkt_max"],
    )

    max_pkt = max(
        fwd_max,
        bwd_max,
    )

    fwd_min = _get_float(
        row,
        COLUMN_ALIASES["fwd_pkt_min"],
    )

    bwd_min = _get_float(
        row,
        COLUMN_ALIASES["bwd_pkt_min"],
    )

    min_candidates = [
        value
        for value in (
            fwd_min,
            bwd_min,
        )
        if value > 0
    ]

    min_pkt = (
        min(min_candidates)
        if min_candidates
        else 0.0
    )

    # -------------------------------------------------------
    # SYN ratio
    # -------------------------------------------------------

    syn = _get_float(
        row,
        COLUMN_ALIASES["syn_count"],
    )

    syn_ratio = syn / max(
        packet_count,
        1.0,
    )

    # -------------------------------------------------------
    # Ports
    # -------------------------------------------------------

    dst_port = _get_float(
        row,
        COLUMN_ALIASES["dst_port"],
    )

    # CSE-CIC-IDS2018 commonly does not provide Source Port.
    # Therefore defaulting to 0 is intentional.
    src_port = _get_float(
        row,
        COLUMN_ALIASES["src_port"],
    )

    # -------------------------------------------------------
    # Protocol
    # -------------------------------------------------------

    protocol_value = _get_raw(
        row,
        COLUMN_ALIASES["protocol"],
        default="",
    )

    protocol_string = str(
        protocol_value
    ).strip()

    proto = _PROTO_MAP.get(
        protocol_string,
        _PROTO_MAP.get(
            protocol_string.lower(),
            "",
        ),
    )

    # -------------------------------------------------------
    # Raw AHRAS feature dictionary
    # -------------------------------------------------------

    raw = {
        "packet_count": packet_count,

        "byte_count": byte_count,

        # A single flow cannot reconstruct AHRAS's
        # multi-flow unique-port behaviour.
        #
        # Therefore keep this as 1 for a valid flow.
        "unique_ports": 1.0,

        "avg_packet_size": avg_pkt,

        "max_packet_size": max_pkt,

        "min_packet_size": min_pkt,

        "packets_per_second": pps,

        "bytes_per_second": bps,

        "duration": duration,

        "protocol_tcp": (
            1.0
            if proto == "tcp"
            else 0.0
        ),

        "protocol_udp": (
            1.0
            if proto == "udp"
            else 0.0
        ),

        "protocol_icmp": (
            1.0
            if proto == "icmp"
            else 0.0
        ),

        "src_port_norm": src_port,

        "dst_port_norm": dst_port,

        "syn_flag_ratio": syn_ratio,

        "has_high_dst_port": (
            1.0
            if dst_port > 1024
            else 0.0
        ),

        "is_known_service_port": (
            1.0
            if int(dst_port) in KNOWN_SVC
            else 0.0
        ),
    }

    # -------------------------------------------------------
    # Build vector using AHRAS's exact FEATURE_NAMES order
    # -------------------------------------------------------

    vector = []

    for feature_name in FEATURE_NAMES:

        value = raw.get(
            feature_name,
            0.0,
        )

        value = _norm_feature(
            feature_name,
            value,
        )

        vector.append(value)

    vector = np.asarray(
        vector,
        dtype=np.float32,
    )

    # -------------------------------------------------------
    # Final safety check
    # -------------------------------------------------------

    if not np.all(
        np.isfinite(vector)
    ):
        return None

    return vector


# ---------------------------------------------------------------------------
# Process one CSV file
# ---------------------------------------------------------------------------

def _process_file(
    path,
    limit_per_file=None,
):
    """
    Extract BENIGN rows from one CSV.

    Returns:
        vectors
        total_rows
        skipped_attack
        skipped_degenerate
    """

    vectors = []

    total_rows = 0
    skipped_attack = 0
    skipped_degenerate = 0

    file_kept = 0

    with open(
        path,
        "r",
        encoding="utf-8-sig",
        errors="ignore",
        newline="",
    ) as fh:

        reader = csv.DictReader(
            fh
        )

        # ---------------------------------------------------
        # Validate headers
        # ---------------------------------------------------

        if not reader.fieldnames:

            logger.warning(
                "%s: no CSV headers found",
                os.path.basename(path),
            )

            return (
                vectors,
                total_rows,
                skipped_attack,
                skipped_degenerate,
            )

        headers = [
            _clean_header(h)
            for h in reader.fieldnames
            if h is not None
        ]

        # Make sure Label exists.
        label_header = None

        for header in headers:

            if header.lower() == "label":
                label_header = header
                break

        if label_header is None:

            logger.warning(
                "%s: Label column not found. Headers detected: %s",
                os.path.basename(path),
                headers[:10],
            )

            return (
                vectors,
                total_rows,
                skipped_attack,
                skipped_degenerate,
            )

        # ---------------------------------------------------
        # Process rows
        # ---------------------------------------------------

        for raw_row in reader:

            # Stop after requested number of BENIGN vectors.
            if (
                limit_per_file is not None
                and limit_per_file > 0
                and file_kept >= limit_per_file
            ):
                break

            row = _clean_row(
                raw_row
            )

            total_rows += 1

            # -----------------------------------------------
            # Label
            # -----------------------------------------------

            label_value = row.get(
                label_header,
                "",
            )

            label = (
                str(label_value)
                .replace("\ufeff", "")
                .strip()
                .lower()
            )

            # -----------------------------------------------
            # Keep only BENIGN/normal traffic
            # -----------------------------------------------

            if label not in _BENIGN_TOKENS:

                skipped_attack += 1

                continue

            # -----------------------------------------------
            # Convert to AHRAS vector
            # -----------------------------------------------

            vector = _row_to_vector(
                row
            )

            if vector is None:

                skipped_degenerate += 1

                continue

            vectors.append(
                vector
            )

            file_kept += 1

    logger.info(
        "%s: kept %d BENIGN flows",
        os.path.basename(path),
        file_kept,
    )

    return (
        vectors,
        total_rows,
        skipped_attack,
        skipped_degenerate,
    )


# ---------------------------------------------------------------------------
# Main processing function
# ---------------------------------------------------------------------------

def run(
    data_dir: str,
    limit_per_file: int = None,
):
    """
    Process all CSV files in data_dir and append their BENIGN
    vectors to data/baseline_normal.npy.
    """

    csv_files = sorted(
        glob.glob(
            os.path.join(
                data_dir,
                "*.csv",
            )
        )
    )

    if not csv_files:

        logger.error(
            "No CSV files found in %s",
            data_dir,
        )

        return

    logger.info(
        "Found %d CSV file(s) in %s",
        len(csv_files),
        data_dir,
    )

    # -------------------------------------------------------
    # Statistics
    # -------------------------------------------------------

    all_vectors = []

    total_rows = 0
    total_kept = 0
    total_skipped_attack = 0
    total_skipped_degenerate = 0

    # -------------------------------------------------------
    # Process every CSV
    # -------------------------------------------------------

    for path in csv_files:

        (
            vectors,
            rows,
            skipped_attack,
            skipped_degenerate,
        ) = _process_file(
            path,
            limit_per_file,
        )

        all_vectors.extend(
            vectors
        )

        total_rows += rows
        total_kept += len(vectors)
        total_skipped_attack += skipped_attack
        total_skipped_degenerate += skipped_degenerate

    # -------------------------------------------------------
    # Nothing found
    # -------------------------------------------------------

    if not all_vectors:

        logger.error(
            "No usable BENIGN rows found across the given CSVs."
        )

        logger.error(
            "Check the dataset path, Label values, and CSV schema."
        )

        return

    # -------------------------------------------------------
    # Convert to numpy array
    # -------------------------------------------------------

    X_new = np.asarray(
        all_vectors,
        dtype=np.float32,
    )

    # -------------------------------------------------------
    # Final validation
    # -------------------------------------------------------

    if X_new.ndim != 2:

        logger.error(
            "Unexpected baseline shape: %s",
            X_new.shape,
        )

        return

    if X_new.shape[1] != len(
        FEATURE_NAMES
    ):

        logger.error(
            "Feature count mismatch: generated=%d expected=%d",
            X_new.shape[1],
            len(FEATURE_NAMES),
        )

        return

    if not np.all(
        np.isfinite(X_new)
    ):

        logger.error(
            "Generated baseline contains NaN or infinite values."
        )

        return

    # -------------------------------------------------------
    # Create data directory
    # -------------------------------------------------------

    os.makedirs(
        "data",
        exist_ok=True,
    )

    # -------------------------------------------------------
    # Append to existing baseline
    # -------------------------------------------------------

    if os.path.exists(
        BASELINE_PATH
    ):

        try:

            X_old = np.load(
                BASELINE_PATH
            )

            # Safety check.
            if (
                X_old.ndim != 2
                or X_old.shape[1]
                != len(FEATURE_NAMES)
            ):

                logger.error(
                    "Existing baseline has incompatible shape: %s",
                    X_old.shape,
                )

                logger.error(
                    "Expected: (?, %d)",
                    len(FEATURE_NAMES),
                )

                return

            X = np.vstack(
                [
                    X_old,
                    X_new,
                ]
            )

            logger.info(
                "Appended %d BENIGN flows to existing baseline "
                "(%d -> %d total vectors).",
                len(X_new),
                len(X_old),
                len(X),
            )

        except Exception as exc:

            logger.error(
                "Could not load existing baseline: %s",
                exc,
            )

            return

    else:

        X = X_new

        logger.info(
            "Started new baseline with %d BENIGN flows.",
            len(X_new),
        )

    # -------------------------------------------------------
    # Save
    # -------------------------------------------------------

    np.save(
        BASELINE_PATH,
        X,
    )

    # -------------------------------------------------------
    # Final statistics
    # -------------------------------------------------------

    logger.info(
        "============================================================"
    )

    logger.info(
        "AHRAS BENIGN BASELINE IMPORT COMPLETE"
    )

    logger.info(
        "============================================================"
    )

    logger.info(
        "Dataset directory: %s",
        data_dir,
    )

    logger.info(
        "CSV files processed: %d",
        len(csv_files),
    )

    logger.info(
        "Rows scanned: %d",
        total_rows,
    )

    logger.info(
        "BENIGN vectors kept: %d",
        total_kept,
    )

    logger.info(
        "Attack/non-BENIGN rows skipped: %d",
        total_skipped_attack,
    )

    logger.info(
        "Degenerate flows skipped: %d",
        total_skipped_degenerate,
    )

    logger.info(
        "Final baseline shape: %s",
        X.shape,
    )

    logger.info(
        "Baseline saved to: %s",
        BASELINE_PATH,
    )

    logger.info(
        "============================================================"
    )

    logger.info(
        "NEXT STEP:"
    )

    logger.info(
        "python retrain_baseline.py train"
    )

    logger.info(
        "============================================================"
    )


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description=(
            "Extract BENIGN-labelled flows from "
            "CICIDS2017 / CSE-CIC-IDS2018 CSV files "
            "and add them to the AHRAS anomaly-model baseline."
        )
    )

    parser.add_argument(
        "--data-dir",
        default="data",
        help=(
            "Folder containing the CSV files. "
            "Example: data/cse_cic_ids2018"
        ),
    )

    parser.add_argument(
        "--limit-per-file",
        type=int,
        default=None,
        help=(
            "Maximum number of BENIGN rows to keep "
            "from each CSV file. Example: 300"
        ),
    )

    args = parser.parse_args()

    run(
        data_dir=args.data_dir,
        limit_per_file=args.limit_per_file,
    )