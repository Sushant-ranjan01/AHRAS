"""AHRAS — Event Manager (Phase 8)"""
import time, socket, threading, logging
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict
try:
    from pymongo import MongoClient, DESCENDING; MONGO_OK=True
except: MONGO_OK=False
from detection.hybrid_detection import DetectionResult
from risk_engine.risk_scorer import RiskScore
from config import config
logger=logging.getLogger("ahras.events")
HOST=socket.gethostname()

@dataclass
class SecurityEvent:
    event_id:str; flow_id:str
    timestamp:float=field(default_factory=time.time); timestamp_str:str=""
    src_ip:str=""; dst_ip:str=""; protocol:str=""; src_port:int=0; dst_port:int=0
    attack_type:str="Normal"; severity:str="LOW"; confidence:float=0.0
    signature_rule:Optional[str]=None; anomaly_label:str="Normal"; anomaly_score:float=0.0
    risk_score:float=0.0; risk_components:Dict=field(default_factory=dict)
    country:str="Unknown"; organization:str="Unknown"; dns_name:str=""; is_private:bool=False
    hostname:str=HOST

    def to_dict(self):
        d=asdict(self)
        if not d["timestamp_str"]:
            d["timestamp_str"]=datetime.fromtimestamp(self.timestamp,tz=timezone.utc).strftime("%H:%M:%S")
        return d

    @classmethod
    def from_detection(cls, det:DetectionResult, risk:RiskScore, eid:str):
        dt=datetime.fromtimestamp(time.time(),tz=timezone.utc)
        return cls(event_id=eid,flow_id=det.flow_id,
                   timestamp_str=dt.strftime("%H:%M:%S"),
                   src_ip=det.src_ip,dst_ip=det.dst_ip,protocol=det.protocol,
                   src_port=det.src_port,dst_port=det.dst_port,
                   attack_type=det.attack_type,severity=risk.severity,
                   confidence=det.confidence,
                   signature_rule=det.signature_result.rule_id if det.signature_result else None,
                   anomaly_label=det.anomaly_result.label if det.anomaly_result else "Normal",
                   anomaly_score=det.anomaly_score,
                   risk_score=risk.overall,risk_components=risk.to_dict().get("components",{}))

class _Mem:
    def __init__(self,mx=2000):
        self._e:List[dict]=[]; self._mx=mx; self._l=threading.Lock()
        from database import EventRepository
        self._repo = EventRepository()
    def insert(self,e):
        with self._l:
            self._e.insert(0,e)
            if len(self._e)>self._mx: self._e.pop()
        try:
            self._repo.save(e)
        except Exception:
            pass
    def recent(self,n=50):
        with self._l: return self._e[:n]
    def count(self):
        with self._l: return len(self._e)
    def sev_counts(self):
        with self._l:
            c={"LOW":0,"MEDIUM":0,"HIGH":0,"CRITICAL":0}
            for e in self._e: c[e.get("severity","LOW")]=c.get(e.get("severity","LOW"),0)+1
            return c
    def attack_counts(self):
        with self._l:
            c={}
            for e in self._e: t=e.get("attack_type","Normal"); c[t]=c.get(t,0)+1
            return c
    def proto_counts(self):
        with self._l:
            c={}
            for e in self._e: p=e.get("protocol","OTHER"); c[p]=c.get(p,0)+1
            return c
    def risk_trend(self,n=30):
        with self._l:
            return [{"time":e.get("timestamp_str",""),"risk":e.get("risk_score",0)}
                    for e in self._e[:n]][::-1]

class EventManager:
    _ctr=0; _lock=threading.Lock()
    def __init__(self):
        self._mem=_Mem()
        self._mongo=None
        if MONGO_OK:
            try:
                c=MongoClient(config.MONGO_URI,serverSelectionTimeoutMS=2000); c.server_info()
                db=c[config.MONGO_DB]; self._col=db["security_events"]
                self._col.create_index([("timestamp",DESCENDING)]); self._mongo=True
                logger.info("MongoDB connected")
            except: logger.warning("MongoDB unavailable — using in-memory store")

    def _next_id(self):
        with EventManager._lock: EventManager._ctr+=1; return f"EVT-{EventManager._ctr:06d}"

    def store(self, det:DetectionResult, risk:RiskScore, enrichment:dict=None) -> SecurityEvent:
        ev=SecurityEvent.from_detection(det,risk,self._next_id())
        if enrichment:
            ev.country      = enrichment.get("country", ev.country)
            ev.organization = enrichment.get("organization", ev.organization)
            ev.dns_name     = enrichment.get("dns_name", ev.dns_name)
            ev.is_private   = enrichment.get("is_private", ev.is_private)
        d=ev.to_dict()
        if self._mongo:
            try:
                self._col.insert_one(d)
                d.pop("_id", None)   # insert_one mutates d with ObjectId — strip it
            except: pass
        self._mem.insert(d)
        return ev

    def recent_events(self,limit=50): return self._mem.recent(limit)
    def total_count(self): return self._mem.count()
    def severity_counts(self): return self._mem.sev_counts()
    def attack_type_counts(self): return self._mem.attack_counts()
    def protocol_counts(self): return self._mem.proto_counts()
    def risk_trend(self,n=30): return self._mem.risk_trend(n)
    def clear(self):
        with self._mem._l:
            self._mem._e.clear()
