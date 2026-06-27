"""AHRAS v4.0 — Asset Management
Tracks network assets with criticality scores.
Risk formula: Risk = Threat + MITRE + ML + Asset Criticality
"""
import time, uuid, threading, logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional
logger = logging.getLogger("ahras.assets")

@dataclass
class Asset:
    asset_id: str
    name: str
    ip: str
    asset_type: str        # server, workstation, dc, router, iot, database, web
    criticality: int       # 1-10 (10 = Domain Controller, 1 = IoT bulb)
    owner: str
    description: str
    tags: List[str]
    os: str = ""
    location: str = ""
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    active: bool = True
    alert_count: int = 0

    def to_dict(self):
        return {
            "asset_id": self.asset_id, "name": self.name, "ip": self.ip,
            "asset_type": self.asset_type, "criticality": self.criticality,
            "owner": self.owner, "description": self.description, "tags": self.tags,
            "os": self.os, "location": self.location, "active": self.active,
            "alert_count": self.alert_count,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.created_at)),
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_seen)),
        }

_SEED = [
    ("Domain Controller",  "192.168.1.1",  "dc",          10, "IT Team",   "Primary AD/DC"),
    ("Web Server",         "192.168.1.10", "web",          8,  "DevOps",    "Public-facing web app"),
    ("Database Server",    "192.168.1.20", "database",     9,  "DBA Team",  "Production database"),
    ("Email Server",       "192.168.1.30", "server",       7,  "IT Team",   "Mail relay"),
    ("Dev Workstation",    "192.168.1.100","workstation",   4,  "Dev Team",  "Developer machine"),
    ("IoT Gateway",        "192.168.1.200","iot",           3,  "Facilities","Building IoT hub"),
    ("Firewall",           "192.168.1.254","router",        9,  "NetOps",    "Perimeter firewall"),
]

_CRITICALITY_LABEL = {10:"Critical Asset",9:"High Value",8:"Important",
                      7:"Significant",6:"Moderate",5:"Standard",4:"Low",3:"Minimal",2:"Negligible",1:"Trivial"}

class AssetManager:
    def __init__(self):
        self._assets: Dict[str,Asset] = {}
        self._ip_index: Dict[str,str] = {}   # ip -> asset_id
        self._lock = threading.Lock()
        self._seed()
        logger.info(f"AssetManager ready — {len(self._assets)} assets loaded")

    def _seed(self):
        for name,ip,atype,crit,owner,desc in _SEED:
            self._create(name,ip,atype,crit,owner,desc,[],""," ")

    def _create(self,name,ip,atype,crit,owner,desc,tags,os,location):
        a=Asset(asset_id=str(uuid.uuid4())[:10],name=name,ip=ip,asset_type=atype,
                criticality=crit,owner=owner,description=desc,tags=tags,os=os,location=location)
        self._assets[a.asset_id]=a
        self._ip_index[ip]=a.asset_id
        return a

    def add_asset(self,name,ip,asset_type,criticality,owner,description,tags=None,os="",location=""):
        with self._lock:
            a=self._create(name,ip,asset_type,int(criticality),owner,description,tags or [],os,location)
        logger.info(f"Asset added: {name} ({ip}) crit={criticality}")
        return a

    def get_by_ip(self,ip:str) -> Optional[Asset]:
        with self._lock:
            aid=self._ip_index.get(ip)
            return self._assets.get(aid) if aid else None

    def get_criticality(self,ip:str) -> Optional[int]:
        a=self.get_by_ip(ip)
        return a.criticality if a else None

    def record_alert(self,ip:str):
        with self._lock:
            aid=self._ip_index.get(ip)
            if aid and aid in self._assets:
                self._assets[aid].alert_count+=1
                self._assets[aid].last_seen=time.time()

    def list_assets(self,active_only=True) -> List[dict]:
        with self._lock:
            assets=[a for a in self._assets.values() if not active_only or a.active]
            return [a.to_dict() for a in sorted(assets,key=lambda x:x.criticality,reverse=True)]

    def delete_asset(self,asset_id:str) -> bool:
        with self._lock:
            if asset_id in self._assets:
                ip=self._assets[asset_id].ip
                self._assets[asset_id].active=False
                self._ip_index.pop(ip,None)
                return True
        return False

    def stats(self) -> dict:
        with self._lock:
            assets=[a for a in self._assets.values() if a.active]
            by_type:Dict[str,int]={}; by_crit:Dict[str,int]={}
            for a in assets:
                by_type[a.asset_type]=by_type.get(a.asset_type,0)+1
                label=_CRITICALITY_LABEL.get(a.criticality,"Unknown")
                by_crit[label]=by_crit.get(label,0)+1
            top_alerted=sorted([a for a in assets if a.alert_count>0],key=lambda x:x.alert_count,reverse=True)[:5]
            return {"total":len(assets),"by_type":by_type,"by_criticality":by_crit,
                    "top_alerted":[{"ip":a.ip,"name":a.name,"alerts":a.alert_count} for a in top_alerted]}
