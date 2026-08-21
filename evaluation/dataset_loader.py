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
from datetime import datetime as _dt
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


def _clean_label(raw: str) -> str:
    """
    Normalize a dataset's raw label/category string for display.

    The public CICIDS2017 CSVs (as distributed by UNB) have a well-documented
    encoding quirk: a few labels -- notably "Web Attack - Brute Force" /
    "- XSS" / "- Sql Injection" -- use an en-dash that was corrupted to the
    Unicode replacement character (U+FFFD, "\ufffd") somewhere in the
    dataset's own publishing pipeline, before AHRAS ever reads the file. It's
    cosmetic (the attack is still classified correctly -- _category_to_
    attack_type() matches on "brute"/"web"/"sql" substrings, not the dash),
    but it looks broken in any report or dashboard that prints the raw label,
    so normalize it to a plain hyphen for anything user-facing.
    """
    if not raw:
        return raw
    return raw.replace("\ufffd", "-").replace("\uFFFD", "-")


@dataclass
class DatasetRecord:
    src_ip: str
    features: Dict[str, float]
    label: int                  # 0=benign, 1=attack (ground truth)
    attack_category: str
    raw_row: Dict[str, str]
    event_time: Optional[float] = None  # epoch seconds from the dataset's own
                                         # timestamp column, when available
                                         # (currently: cicids2017 only). None
                                         # for datasets with no real per-row
                                         # timing (NSL-KDD, UNSW-NB15, generic).

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip, "features": self.features,
            "label": self.label, "attack_category": self.attack_category,
            "event_time": self.event_time,
        }


def _parse_cicids_timestamp(raw: str) -> Optional[float]:
    """
    Best-effort parse of CICIDS2017's 'Timestamp' column into epoch seconds.
    The public CSVs are inconsistent about format across the week's files
    (some have seconds, some have AM/PM, some don't) so this tries several
    known variants and gives up cleanly (returns None) rather than raising --
    a record with no parseable timestamp just falls back to RiskEngine's
    wall-clock behavior for that one record, it never crashes the run.
    """
    if not raw:
        return None
    raw = raw.strip()
    for fmt in ("%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M",
                "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"):
        try:
            return _dt.strptime(raw, fmt).timestamp()
        except ValueError:
            continue
    return None


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

    def iter_records(self, limit: Optional[int] = None,
                      sample: bool = False) -> Iterator[DatasetRecord]:
        """
        limit=None            -> every record in the file (most correct, slowest).
        limit=N, sample=False -> the first N records (legacy/default: fast,
                                  but see warning below).
        limit=N, sample=True  -> N records reservoir-sampled uniformly at
                                  random from the WHOLE file in a single pass.

        WHY sample=True MATTERS: public per-day CICIDS2017 files are stored
        in chronological order and each day's file is 200k-700k+ rows, with
        the actual attack traffic concentrated in a specific window (e.g.
        Wednesday's DoS attacks start well after 9am). `limit=20000` with
        sample=False only ever reads the first 20000 lines of the file --
        for a large file that is early-morning benign traffic, so a report
        can come back showing "1 attack out of 20000 rows" purely because
        of where the read stopped, not because the file only has 1 attack.
        The resulting precision numbers are then dominated by a single
        (or a handful of) positive sample and look far worse than the
        detector's real behavior. sample=True fixes this by giving every
        row in the file an equal chance of being included, so rare/late
        attack classes are represented proportionally to their real
        frequency in the full day's traffic.
        """
        raw = self._iter_raw()
        if limit is None:
            yield from raw
            return
        if not sample:
            for i, rec in enumerate(raw):
                if i >= limit:
                    return
                yield rec
            return
        # Reservoir sampling (Algorithm R) -- single pass, O(limit) memory,
        # uniform sample of size `limit` over an unknown-length stream.
        import random
        reservoir: List[DatasetRecord] = []
        for i, rec in enumerate(raw):
            if i < limit:
                reservoir.append(rec)
            else:
                j = random.randint(0, i)
                if j < limit:
                    reservoir[j] = rec
        yield from reservoir

    def _iter_raw(self) -> Iterator[DatasetRecord]:
        """Yields every record in the file, dataset-type dispatch, no limit."""
        if self.dataset_type == "nsl-kdd":
            yield from self._iter_nslkdd(None)
        elif self.dataset_type == "cicids2017":
            yield from self._iter_cicids(None)
        elif self.dataset_type == "unsw-nb15":
            yield from self._iter_unsw(None)
        else:
            yield from self._iter_generic(None)

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
                    label=label, attack_category=_clean_label(label_raw), raw_row=row_dict,
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
                event_time = _parse_cicids_timestamp(row.get("Timestamp", ""))
                count += 1
                yield DatasetRecord(
                    src_ip=src_ip, features=features, label=label,
                    attack_category=_clean_label(row.get("Label", "Unknown")), raw_row=row,
                    event_time=event_time,
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
                    attack_category=_clean_label(row.get("attack_cat", "Normal") or "Normal"),
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
                    label=label, attack_category=_clean_label(str(label_raw)), raw_row=row,
                )

    def count_records(self, limit: Optional[int] = None) -> int:
        return sum(1 for _ in self.iter_records(limit=limit))
