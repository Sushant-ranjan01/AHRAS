"""AHRAS ML model registry and lifecycle metadata."""
from __future__ import annotations
import hashlib, json, os, shutil, time
from pathlib import Path
from typing import Any

class ModelRegistry:
    def __init__(self, model_path: str = "models/isolation_forest.joblib", registry_dir: str = "models/registry"):
        self.model_path = Path(model_path)
        self.registry_dir = Path(registry_dir)
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.registry_dir / "registry.json"
        self._index = self._load()

    def _load(self):
        if self.index_path.exists():
            try: return json.loads(self.index_path.read_text(encoding="utf-8"))
            except Exception: pass
        return {"models": [], "active_version": None}

    def _save(self):
        self.index_path.write_text(json.dumps(self._index, indent=2), encoding="utf-8")

    def _sha256(self, path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""): h.update(chunk)
        return h.hexdigest()

    def register(self, version: str, metrics: dict | None = None, metadata: dict | None = None) -> dict:
        if not self.model_path.exists(): raise FileNotFoundError(str(self.model_path))
        artifact = self.registry_dir / f"{version}.joblib"
        shutil.copy2(self.model_path, artifact)
        entry = {
            "version": version, "artifact": str(artifact), "sha256": self._sha256(artifact),
            "created_at": time.time(), "metrics": metrics or {}, "metadata": metadata or {},
        }
        self._index["models"] = [m for m in self._index["models"] if m.get("version") != version]
        self._index["models"].append(entry); self._index["active_version"] = version; self._save()
        return entry

    def list_models(self): return sorted(self._index["models"], key=lambda x: x.get("created_at", 0), reverse=True)
    def active(self):
        v = self._index.get("active_version")
        return next((m for m in self._index["models"] if m.get("version") == v), None)
    def promote(self, version: str):
        model = next((m for m in self._index["models"] if m.get("version") == version), None)
        if not model: raise KeyError(version)
        shutil.copy2(model["artifact"], self.model_path)
        self._index["active_version"] = version; self._save(); return model

    def metadata(self):
        active = self.active()
        return {"active_version": self._index.get("active_version"), "active": active, "count": len(self._index["models"])}
