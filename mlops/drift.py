"""Feature-distribution drift detection using PSI and summary statistics."""
from __future__ import annotations
import numpy as np

class DriftDetector:
    def __init__(self, psi_threshold=0.20): self.psi_threshold = float(psi_threshold)
    @staticmethod
    def psi(reference, current, bins=10):
        ref=np.asarray(reference,dtype=float); cur=np.asarray(current,dtype=float)
        if ref.ndim != 2 or cur.ndim != 2 or ref.shape[1] != cur.shape[1]: raise ValueError("reference/current feature dimensions must match")
        vals=[]
        for j in range(ref.shape[1]):
            edges=np.unique(np.quantile(ref[:,j], np.linspace(0,1,bins+1)))
            if len(edges)<3: vals.append(0.0); continue
            a=np.histogram(ref[:,j],edges)[0].astype(float)+1e-6; b=np.histogram(cur[:,j],edges)[0].astype(float)+1e-6
            a/=a.sum(); b/=b.sum(); vals.append(float(np.sum((b-a)*np.log(b/a))))
        return np.asarray(vals)
    def report(self, reference, current, feature_names=None):
        scores=self.psi(reference,current); names=feature_names or [f"feature_{i}" for i in range(len(scores))]
        items=[{"feature":n,"psi":round(float(s),6),"drifted":bool(s>=self.psi_threshold)} for n,s in zip(names,scores)]
        return {"psi_threshold":self.psi_threshold,"drifted_features":sum(x["drifted"] for x in items),"drift_detected":any(x["drifted"] for x in items),"features":items}
