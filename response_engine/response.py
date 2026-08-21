"""AHRAS — Response Engine (Phase 9)"""
import time, platform, subprocess, threading, logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Set, Dict, List, Optional, Callable, Deque
from event_management.event_manager import SecurityEvent
from config import config
logger=logging.getLogger("ahras.response")
OS=platform.system()

@dataclass
class Alert:
    alert_id:str; event_id:str; src_ip:str; attack_type:str
    severity:str; risk_score:float
    timestamp:float=field(default_factory=time.time)
    message:str=""; acknowledged:bool=False
    def to_dict(self):
        return {"alert_id":self.alert_id,"event_id":self.event_id,"src_ip":self.src_ip,
                "attack_type":self.attack_type,"severity":self.severity,
                "risk_score":self.risk_score,"timestamp":self.timestamp,
                "message":self.message,"acknowledged":self.acknowledged}

class AlertSystem:
    _ctr=0
    def __init__(self,on_alert:Optional[Callable]=None):
        self._alerts:List[Alert]=[]; self._lock=threading.Lock(); self._cb=on_alert
    def evaluate(self,ev:SecurityEvent)->Optional[Alert]:
        if ev.severity not in ("HIGH","CRITICAL"): return None
        AlertSystem._ctr+=1
        a=Alert(f"ALT-{AlertSystem._ctr:05d}",ev.event_id,ev.src_ip,
                ev.attack_type,ev.severity,ev.risk_score,
                message=f"[{ev.severity}] {ev.attack_type} from {ev.src_ip} risk={ev.risk_score:.2f}")
        with self._lock:
            self._alerts.insert(0,a)
            if len(self._alerts)>500: self._alerts.pop()
        logger.warning(f"ALERT {a.alert_id}: {a.message}")
        if self._cb: self._cb(a)
        return a
    def recent_alerts(self,n=20):
        with self._lock: return [a.to_dict() for a in self._alerts[:n]]
    def acknowledge(self,aid:str)->bool:
        with self._lock:
            for a in self._alerts:
                if a.alert_id==aid: a.acknowledged=True; return True
        return False

class RateLimiter:
    def __init__(self,max_ev=30,win=10.0):
        self.max=max_ev; self.win=win
        self._b:Dict[str,Deque[float]]=defaultdict(deque); self._l=threading.Lock()
    def check(self,ip)->bool:
        now=time.time()
        with self._l:
            d=self._b[ip]; d.append(now); cut=now-self.win
            while d and d[0]<cut: d.popleft()
            return len(d)>self.max

class IPBlocker:
    DRY_RUN=True
    def __init__(self):
        self._blocked:Set[str]=set(); self._l=threading.Lock()
    @property
    def blocked_ips(self):
        with self._l: return set(self._blocked)
    def block(self,ip)->bool:
        with self._l:
            if ip in self._blocked: return False
            self._blocked.add(ip)
        if not self.DRY_RUN: self._apply(ip,True)
        return True
    def unblock(self,ip)->bool:
        with self._l:
            if ip not in self._blocked: return False
            self._blocked.discard(ip)
        if not self.DRY_RUN: self._apply(ip,False)
        return True
    def _apply(self,ip,block):
        action="INPUT" if block else "delete"
        try:
            if OS=="Linux":
                args=["iptables","-I","INPUT","-s",ip,"-j","DROP"] if block else ["iptables","-D","INPUT","-s",ip,"-j","DROP"]
                subprocess.run(args,check=True)
        except Exception as e: logger.error(f"FW error: {e}")

class ResponseEngine:
    AUTO_BLOCK=9.0
    def __init__(self,trust_engine=None):
        self.alerts=AlertSystem(); self.rate=RateLimiter()
        self.ip_blocker=IPBlocker(); self._trust=trust_engine
    def handle(self,ev:SecurityEvent)->dict:
        actions=[]
        if self.rate.check(ev.src_ip): actions.append(f"rate_limited:{ev.src_ip}")
        a=self.alerts.evaluate(ev)
        if a: actions.append(f"alert:{a.alert_id}")
        if ev.risk_score>=self.AUTO_BLOCK:
            if self.ip_blocker.block(ev.src_ip):
                actions.append(f"blocked:{ev.src_ip}")
                if self._trust: self._trust.add_blacklist(ev.src_ip)
        return {"actions":actions,"event_id":ev.event_id}
