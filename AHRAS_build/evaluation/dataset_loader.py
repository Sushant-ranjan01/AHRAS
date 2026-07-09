"""
AHRAS v4 -- Public Dataset Evaluation: Dataset Loader
=======================================================
Loads and normalizes public intrusion-detection datasets into a single
common schema so the SAME evaluation runner works against any of them.

Supported datasets (all CSV-based, all freely downloadable):

  CICIDS2017 (Canadian Institute for Cybersecurity)
    https://www.unb.ca/cic/datasets/ids-2017.html
    Columns include 'Label' (BENIGN / attack name), flow-level features.

  NSL-KDD (improved KDD'99)
    https://www.unb.ca/cic/datasets/nsl.html
    41 features + 'label' (normal / attack name) + difficulty.

  UNSW-NB15
    https://research.unsw.edu.au/projects/unsw-nb15-dataset
    49 features + 'label' (0=normal,1=attack) + 'attack_cat'.

You download the CSV(s) yourself (datasets are multi-GB, not bundled),
place them in a folder, and point DatasetLoader at that folder. The
loader auto-detects which dataset it is from the column names and
normalizes to:

    {
      "src_ip": str (synthetic if dataset has no real IP, e.g. NSL-KDD),
      "features": {...raw numeric features as a dict...},
      "label": 0 or 1,            # ground truth: 0=benign, 1=attack
      "attack_category": str,     # original label string
    }

This normalized form feeds directly into EvaluationRunner, which maps
features onto AHRAS's detection.HybridDetectionEngine input schema.
"""
import csv
import logging
import os
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional

logger = logging.getLogger("ahras.evaluation.dataset")

# Column-name signatures used to auto-detect dataset type
_CICIDS_MARKERS = {"Flow Duration", "Total Fwd Packets", "Label"}
_NSLKDD_COLUMNS = [  # NSL-KDD has no header row in the raw file; this is the known schema
    "duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
    "wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations","num_shells",
    "num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count",
    "srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "label","difficulty",
]
_UNSW_MARKERS = {"attack_cat", "label", "dur", "proto"}

# Benign / normal label tokens across datasets (case-insensitive)
_BENIGN_TOKENS = {"benign", "normal", "normal."}


@dataclass
class DatasetRecord:
    src_ip: str
    features: Dict[str, float]
    label: int                  # 0=benign, 1=attack (ground truth)
    attack_category: str
    raw_row: Dict[str, str]

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip, "features": self.features,
            "label": self.label, "attack_category": self.attack_category,
        }


class DatasetLoader:
    """
    Usage:
        loader = DatasetLoader("/path/to/CICIDS2017_sample.csv")
        for record in loader.iter_records(limit=10000):
            ...

    Or for an entire folder of CSVs (CICIDS2017 ships as multiple
    per-day files):
        loader = DatasetLoader.from_folder("/path/to/cicids_folder")
    """

    def __init__(self, filepath: str, dataset_type: Optional[str] = None):
        self.filepath = filepath
        self.dataset_type = dataset_type or self._detect_type(filepath)
        logger.info(f"DatasetLoader: {filepath} detected as {self.dataset_type}")

    @classmethod
    def from_folder(cls, folder: str) -> List["DatasetLoader"]:
        """Returns one loader per CSV file found in the folder."""
        loaders = []
        for fname in sorted(os.listdir(folder)):
            if fname.lower().endswith(".csv"):
                loaders.append(cls(os.path.join(folder, fname)))
        if not loaders:
            raise FileNotFoundError(f"No CSV files found in {folder}")
        return loaders

    def _detect_type(self, filepath: str) -> str:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline().strip()
            cols = set(c.strip().strip('"') for c in first_line.split(","))
        except Exception:
            return "unknown"

        if _CICIDS_MARKERS.issubset(cols) or any("Flow" in c for c in cols):
            return "cicids2017"
        if _UNSW_MARKERS.issubset({c.lower() for c in cols}):
            return "unsw-nb15"
        if len(cols) >= 40 and "duration" not in cols and "," in first_line:
            # NSL-KDD raw files have no header -- 41-42 comma fields, first numeric
            parts = first_line.split(",")
            if len(parts) in (41, 42):
                return "nsl-kdd"
        return "generic-csv"

    def iter_records(self, limit: Optional[int] = None) -> Iterator[DatasetRecord]:
        if self.dataset_type == "nsl-kdd":
            yield from self._iter_nslkdd(limit)
        elif self.dataset_type == "cicids2017":
            yield from self._iter_cicids(limit)
        elif self.dataset_type == "unsw-nb15":
            yield from self._iter_unsw(limit)
        else:
            yield from self._iter_generic(limit)

    # -- Per-dataset parsers --------------------------------------------------
    def _iter_nslkdd(self, limit: Optional[int]) -> Iterator[DatasetRecord]:
        count = 0
        with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                if limit and count >= limit:
                    return
                if len(row) < 42:
                    continue
                row_dict = dict(zip(_NSLKDD_COLUMNS, row))
                label_raw = row_dict.get("label", "normal").strip().lower()
                label = 0 if label_raw in _BENIGN_TOKENS else 1
                features = {}
                for k in ["duration","src_bytes","dst_bytes","count","srv_count",
                          "serror_rate","srv_serror_rate","same_srv_rate",
                          "diff_srv_rate","dst_host_count","dst_host_srv_count",
                          "num_failed_logins","logged_in"]:
                    try: features[k] = float(row_dict.get(k, 0))
                    except (ValueError, TypeError): features[k] = 0.0
                count += 1
                yield DatasetRecord(
                    src_ip=f"nslkdd-synthetic-{count}", features=features,
                    label=label, attack_category=label_raw, raw_row=row_dict,
                )

    def _iter_cicids(self, limit: Optional[int]) -> Iterator[DatasetRecord]:
        count = 0
        with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if limit and count >= limit:
                    return
                row = {k.strip(): v for k, v in row.items() if k}
                label_raw = (row.get("Label", "") or "").strip().lower()
                label = 0 if label_raw in _BENIGN_TOKENS else 1
                features = {}
                for k in ["Flow Duration", "Total Fwd Packets", "Total Backward Packets",
                          "Flow Bytes/s", "Flow Packets/s", "SYN Flag Count",
                          "ACK Flag Count", "Average Packet Size", "Packet Length Std",
                          "Destination Port"]:
                    try: features[k] = float(row.get(k, 0) or 0)
                    except (ValueError, TypeError): features[k] = 0.0
                src_ip = row.get("Source IP", row.get(" Source IP", f"cicids-synthetic-{count}"))
                count += 1
                yield DatasetRecord(
                    src_ip=src_ip, features=features, label=label,
                    attack_category=row.get("Label", "Unknown"), raw_row=row,
                )

    def _iter_unsw(self, limit: Optional[int]) -> Iterator[DatasetRecord]:
        count = 0
        with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if limit and count >= limit:
                    return
                row = {k.strip().lower(): v for k, v in row.items() if k}
                label_raw = (row.get("label", "0") or "0").strip()
                label = 1 if label_raw == "1" else 0
                features = {}
                for k in ["dur","sbytes","dbytes","spkts","dpkts","rate",
                          "sttl","dttl","sload","dload","swin","dwin"]:
                    try: features[k] = float(row.get(k, 0) or 0)
                    except (ValueError, TypeError): features[k] = 0.0
                src_ip = row.get("srcip", f"unsw-synthetic-{count}")
                count += 1
                yield DatasetRecord(
                    src_ip=src_ip, features=features, label=label,
                    attack_category=row.get("attack_cat", "Normal") or "Normal",
                    raw_row=row,
                )

    def _iter_generic(self, limit: Optional[int]) -> Iterator[DatasetRecord]:
        """Fallback for unrecognized CSVs -- looks for any column named
        'label'/'Label'/'class' to derive ground truth, treats all other
        numeric columns as features."""
        count = 0
        with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            label_col = None
            for fn in (reader.fieldnames or []):
                if fn.strip().lower() in ("label", "class", "attack", "target"):
                    label_col = fn
                    break
            for row in reader:
                if limit and count >= limit:
                    return
                label_raw = (row.get(label_col, "0") if label_col else "0") or "0"
                label = 0 if str(label_raw).strip().lower() in (_BENIGN_TOKENS | {"0"}) else 1
                features = {}
                for k, v in row.items():
                    if k == label_col or v is None:
                        continue
                    try: features[k] = float(v)
                    except (ValueError, TypeError): continue
                count += 1
                yield DatasetRecord(
                    src_ip=f"generic-synthetic-{count}", features=features,
                    label=label, attack_category=str(label_raw), raw_row=row,
                )

    def count_records(self, limit: Optional[int] = None) -> int:
        return sum(1 for _ in self.iter_records(limit=limit))
