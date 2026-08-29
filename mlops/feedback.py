"""Persistent model-feedback records for analyst-labelled outcomes."""
from __future__ import annotations
import json, time
from pathlib import Path

class FeedbackStore:
    def __init__(self, path="data/ml_feedback.jsonl"): self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True)
    def add(self, *, alert_id, label, model_version=None, prediction=None, features=None, analyst=None, reason=None):
        if label not in (0,1): raise ValueError("label must be 0 or 1")
        row={"timestamp":time.time(),"alert_id":alert_id,"label":label,"model_version":model_version,"prediction":prediction,"features":features or {},"analyst":analyst,"reason":reason}
        with self.path.open("a",encoding="utf-8") as f: f.write(json.dumps(row,separators=(",",":"))+"\n")
        return row
    def summary(self):
        rows=[]
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                try: rows.append(json.loads(line))
                except Exception: pass
        by_model={}
        for r in rows:
            v=r.get("model_version") or "unknown"
            by_model.setdefault(v,{"total":0,"true_positive":0,"false_positive":0})
            by_model[v]["total"] += 1
            by_model[v]["true_positive"] += int(r.get("label")==1)
            by_model[v]["false_positive"] += int(r.get("label")==0)
        return {"total":len(rows),"true_positive":sum(r.get("label")==1 for r in rows),"false_positive":sum(r.get("label")==0 for r in rows),"by_model":by_model}
