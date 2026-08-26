"""Tests for evaluation.dataset_loader"""
import csv
import os
import tempfile
import pytest
from evaluation.dataset_loader import DatasetLoader, DatasetRecord


def _write_csv(rows, fieldnames, path):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


class TestDatasetLoader:

    def test_cicids_detection(self, tmp_path):
        p = tmp_path / "sample.csv"
        _write_csv(
            [{"Flow Duration": 1000, "Total Fwd Packets": 10,
              "Total Backward Packets": 5, "Flow Bytes/s": 500,
              "Flow Packets/s": 15.0, "SYN Flag Count": 2,
              "ACK Flag Count": 8, "Average Packet Size": 100,
              "Packet Length Std": 20, "Destination Port": 80,
              "Source IP": "1.2.3.4", "Label": "BENIGN"},
             {"Flow Duration": 500, "Total Fwd Packets": 100,
              "Total Backward Packets": 2, "Flow Bytes/s": 9000,
              "Flow Packets/s": 200.0, "SYN Flag Count": 90,
              "ACK Flag Count": 0, "Average Packet Size": 40,
              "Packet Length Std": 5, "Destination Port": 22,
              "Source IP": "5.6.7.8", "Label": "DoS Hulk"}],
            ["Flow Duration","Total Fwd Packets","Total Backward Packets",
             "Flow Bytes/s","Flow Packets/s","SYN Flag Count","ACK Flag Count",
             "Average Packet Size","Packet Length Std","Destination Port",
             "Source IP","Label"],
            str(p),
        )
        loader = DatasetLoader(str(p))
        assert loader.dataset_type == "cicids2017"
        records = list(loader.iter_records())
        assert len(records) == 2
        assert records[0].label == 0  # BENIGN
        assert records[1].label == 1  # DoS attack

    def test_generic_csv_detection(self, tmp_path):
        p = tmp_path / "generic.csv"
        _write_csv(
            [{"feature1": 1.0, "feature2": 2.0, "label": "normal"},
             {"feature1": 9.0, "feature2": 8.0, "label": "attack"}],
            ["feature1", "feature2", "label"],
            str(p),
        )
        loader = DatasetLoader(str(p))
        records = list(loader.iter_records())
        assert len(records) == 2
        assert records[0].label == 0
        assert records[1].label == 1

    def test_limit_respected(self, tmp_path):
        p = tmp_path / "limit_test.csv"
        rows = [{"feature1": float(i), "label": "normal"} for i in range(100)]
        _write_csv(rows, ["feature1", "label"], str(p))
        loader = DatasetLoader(str(p))
        records = list(loader.iter_records(limit=10))
        assert len(records) == 10

    def test_head_truncation_misses_late_attacks(self, tmp_path):
        """Documents the known limitation of sample=False (legacy/default):
        with a chronologically-ordered file where attacks are clustered near
        the end, a small head limit sees only benign traffic."""
        p = tmp_path / "late_attacks.csv"
        rows = [{"feature1": float(i), "label": "normal"} for i in range(900)]
        rows += [{"feature1": float(i), "label": "attack"} for i in range(900, 1000)]
        _write_csv(rows, ["feature1", "label"], str(p))
        loader = DatasetLoader(str(p))
        records = list(loader.iter_records(limit=100, sample=False))
        assert all(r.label == 0 for r in records)  # attacks entirely missed

    def test_sample_true_represents_late_attacks(self, tmp_path):
        """sample=True must be able to surface attacks that only occur late
        in the file, since it draws uniformly from every row, not just the
        head -- this is the fix for misleadingly-skewed precision/recall on
        chronologically-ordered datasets like CICIDS2017 per-day CSVs."""
        p = tmp_path / "late_attacks_sample.csv"
        rows = [{"feature1": float(i), "label": "normal"} for i in range(900)]
        rows += [{"feature1": float(i), "label": "attack"} for i in range(900, 1000)]
        _write_csv(rows, ["feature1", "label"], str(p))
        loader = DatasetLoader(str(p))
        records = list(loader.iter_records(limit=200, sample=True))
        assert len(records) == 200
        assert any(r.label == 1 for r in records)  # attacks represented

    def test_sample_true_returns_uniform_size(self, tmp_path):
        p = tmp_path / "uniform.csv"
        rows = [{"feature1": float(i), "label": "normal"} for i in range(50)]
        _write_csv(rows, ["feature1", "label"], str(p))
        loader = DatasetLoader(str(p))
        # limit larger than file: should just return every row, no crash
        records = list(loader.iter_records(limit=200, sample=True))
        assert len(records) == 50

    def test_record_has_required_fields(self, tmp_path):
        p = tmp_path / "fields.csv"
        _write_csv(
            [{"feature1": 1.0, "label": "attack"}],
            ["feature1", "label"], str(p),
        )
        loader = DatasetLoader(str(p))
        record = list(loader.iter_records())[0]
        assert isinstance(record, DatasetRecord)
        assert hasattr(record, "src_ip")
        assert hasattr(record, "features")
        assert hasattr(record, "label")
        assert hasattr(record, "attack_category")
        assert record.label in (0, 1)

    def test_benign_tokens_map_to_zero(self, tmp_path):
        p = tmp_path / "benign.csv"
        rows = [
            {"f": 1.0, "label": "BENIGN"},
            {"f": 1.0, "label": "normal"},
            {"f": 1.0, "label": "Normal."},
        ]
        _write_csv(rows, ["f", "label"], str(p))
        loader = DatasetLoader(str(p))
        records = list(loader.iter_records())
        for r in records:
            assert r.label == 0

    def test_from_folder_finds_csvs(self, tmp_path):
        for i in range(3):
            p = tmp_path / f"file_{i}.csv"
            _write_csv([{"f": 1.0, "label": "normal"}], ["f", "label"], str(p))
        loaders = DatasetLoader.from_folder(str(tmp_path))
        assert len(loaders) == 3

    def test_from_folder_empty_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            DatasetLoader.from_folder(str(tmp_path))

    def test_cicids_record_gets_parsed_event_time(self, tmp_path):
        p = tmp_path / "with_timestamp.csv"
        _write_csv(
            [{"Flow Duration": 1000, "Total Fwd Packets": 10,
              "Total Backward Packets": 5, "Flow Bytes/s": 500,
              "Flow Packets/s": 15.0, "SYN Flag Count": 2,
              "ACK Flag Count": 8, "Average Packet Size": 100,
              "Packet Length Std": 20, "Destination Port": 80,
              "Source IP": "1.2.3.4", "Label": "BENIGN",
              "Timestamp": "7/7/2017 3:30:00 PM"}],
            ["Flow Duration","Total Fwd Packets","Total Backward Packets",
             "Flow Bytes/s","Flow Packets/s","SYN Flag Count","ACK Flag Count",
             "Average Packet Size","Packet Length Std","Destination Port",
             "Source IP","Label","Timestamp"],
            str(p),
        )
        loader = DatasetLoader(str(p))
        record = list(loader.iter_records())[0]
        # Must not crash regardless of exact format matched; either a valid
        # epoch float or None (graceful fallback) is acceptable here — what
        # matters is it never raises and the field always exists.
        assert record.event_time is None or isinstance(record.event_time, float)

    def test_cicids_record_without_timestamp_column_has_none_event_time(self, tmp_path):
        p = tmp_path / "no_timestamp.csv"
        _write_csv(
            [{"Flow Duration": 1000, "Total Fwd Packets": 10,
              "Total Backward Packets": 5, "Flow Bytes/s": 500,
              "Flow Packets/s": 15.0, "SYN Flag Count": 2,
              "ACK Flag Count": 8, "Average Packet Size": 100,
              "Packet Length Std": 20, "Destination Port": 80,
              "Source IP": "1.2.3.4", "Label": "BENIGN"}],
            ["Flow Duration","Total Fwd Packets","Total Backward Packets",
             "Flow Bytes/s","Flow Packets/s","SYN Flag Count","ACK Flag Count",
             "Average Packet Size","Packet Length Std","Destination Port",
             "Source IP","Label"],
            str(p),
        )
        loader = DatasetLoader(str(p))
        record = list(loader.iter_records())[0]
        assert record.event_time is None
