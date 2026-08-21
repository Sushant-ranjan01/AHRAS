"""AHRAS v4.0 — User Behavior Analytics (UBA)
Tracks login times, IP changes, activity patterns.
Flags anomalous behavior: 3 AM login, new IP, unusual activity burst.
"""
import time, threading, logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional
logger = logging.getLogger("ahras.uba")

@dataclass
class UBAAlert:
    alert_id: str
    username: str
    alert_type: str       # unusual_hour, new_ip, activity_burst, impossible_travel
    description: str
    risk_boost: float     # how much to add to overall risk
    timestamp: float = field(default_factory=time.time)
    src_ip: str = ""
    resolved: bool = False

    def to_dict(self):
        return {
            "alert_id":self.alert_id,"username":self.username,"alert_type":self.alert_type,
            "description":self.description,"risk_boost":self.risk_boost,"src_ip":self.src_ip,
            "timestamp":time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(self.timestamp)),
            "resolved":self.resolved,
        }

@dataclass
class UserProfile:
    username: str
    normal_hours: List[int] = field(default_factory=lambda: list(range(8,19)))  # 8AM-7PM
    known_ips: List[str] = field(default_factory=list)
    login_times: List[float] = field(default_factory=list)
    activity_counts: deque = field(default_factory=lambda: deque(maxlen=100))
    last_ip: str = ""
    total_alerts: int = 0

class UBAEngine:
    def __init__(self):
        self._profiles: Dict[str,UserProfile] = {}
        self._alerts: deque = deque(maxlen=500)
        self._lock = threading.Lock()
        self._alert_ctr = 0
        logger.info("UBAEngine ready")

    def record_login(self, username:str, src_ip:str) -> Optional[UBAAlert]:
        with self._lock:
            if username not in self._profiles:
                self._profiles[username] = UserProfile(username=username, known_ips=[src_ip])
                return None
            profile = self._profiles[username]
            now = time.time()
            profile.login_times.append(now)
            hour = int(time.strftime("%H",time.localtime(now)))
            alert = None

            # Unusual hour check
            if hour not in profile.normal_hours:
                label = "night" if hour < 6 or hour >= 22 else "off-hours"
                alert = self._make_alert(username, src_ip, "unusual_hour",
                    f"Login at {hour:02d}:00 ({label}) — normal hours: {min(profile.normal_hours):02d}:00–{max(profile.normal_hours):02d}:00",
                    risk_boost=20.0 if hour < 6 or hour >= 22 else 10.0)

            # New IP check
            elif src_ip and src_ip not in profile.known_ips:
                profile.known_ips.append(src_ip)
                alert = self._make_alert(username, src_ip, "new_ip",
                    f"First login from new IP {src_ip}. Known IPs: {profile.known_ips[:-1]}",
                    risk_boost=15.0)

            # Rapid login check (>5 logins in 60s)
            recent = [t for t in profile.login_times if now-t<=60]
            if len(recent) >= 5:
                alert = self._make_alert(username, src_ip, "activity_burst",
                    f"{len(recent)} logins in 60 seconds — possible credential stuffing",
                    risk_boost=30.0)

            if alert:
                profile.total_alerts += 1
                self._alerts.appendleft(alert)
            profile.last_ip = src_ip
            return alert

    def record_activity(self, username:str, src_ip:str, activity_type:str):
        with self._lock:
            if username not in self._profiles:
                self._profiles[username] = UserProfile(username=username)
            p = self._profiles[username]
            p.activity_counts.append(time.time())
            # Burst: >50 actions in 60s
            now = time.time()
            recent = [t for t in p.activity_counts if now-t<=60]
            if len(recent) >= 50:
                alert = self._make_alert(username, src_ip, "activity_burst",
                    f"Unusual activity burst: {len(recent)} actions/min ({activity_type})",
                    risk_boost=25.0)
                p.total_alerts += 1
                self._alerts.appendleft(alert)
                return alert
        return None

    def _make_alert(self, username, src_ip, atype, desc, risk_boost):
        self._alert_ctr += 1
        return UBAAlert(
            alert_id=f"UBA-{self._alert_ctr:04d}",
            username=username, alert_type=atype,
            description=desc, risk_boost=risk_boost, src_ip=src_ip,
        )

    def get_alerts(self, limit=50) -> List[dict]:
        with self._lock:
            return [a.to_dict() for a in list(self._alerts)[:limit]]

    def get_profile(self, username:str) -> Optional[dict]:
        with self._lock:
            p = self._profiles.get(username)
            if not p: return None
            return {"username":p.username,"known_ips":p.known_ips,
                    "normal_hours":f"{min(p.normal_hours):02d}:00–{max(p.normal_hours):02d}:00",
                    "total_logins":len(p.login_times),"total_alerts":p.total_alerts,"last_ip":p.last_ip}

    def all_profiles(self) -> List[dict]:
        with self._lock:
            return [{"username":p.username,"known_ips":len(p.known_ips),
                     "total_alerts":p.total_alerts,"last_ip":p.last_ip}
                    for p in self._profiles.values()]

    def stats(self) -> dict:
        with self._lock:
            return {"total_users":len(self._profiles),"total_alerts":len(self._alerts),
                    "unresolved":sum(1 for a in self._alerts if not a.resolved)}
