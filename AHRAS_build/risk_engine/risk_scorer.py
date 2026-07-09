"""
AHRAS v4.0 — Advanced Risk Engine
Merges working version's multi-signal weighted fusion WITH v3 MITRE boosts + asset criticality.

Risk Formula:
  R = (α·Sig + β·Anomaly + γ·Density + δ·(Drift+Rate)) * 100
    + MITRE severity boost + Asset criticality boost - Trust reduction
"""
import time, socket, logging
from collections import defaultdict
logger = logging.getLogger("ahras.risk")

_TRUSTED = ["google","amazonaws","cloudflare","microsoft","facebook","akamai","fastly","apple","github"]

_MITRE_BOOST = {
    "T1486":25,"T1041":20,"T1021":18,"T1095":15,"T1071":12,
    "T1110":10,"T1190":15,"T1498":8,"T1046":5,
}

def _safe(v, d=0.0):
    if v is None: return d
    if isinstance(v,(int,float)): return float(v)
    try: return float(v)
    except: return d

def _is_private(ip: str) -> bool:
    """Return True for RFC-1918 / loopback / link-local addresses."""
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4: return False
        a, b = parts[0], parts[1]
        return (a == 10 or a == 127 or
                (a == 172 and 16 <= b <= 31) or
                (a == 192 and b == 168) or
                (a == 169 and b == 254))
    except Exception:
        return False

_TRUST_CACHE: dict = {}          # ip -> (trust, domain) — avoids re-resolving on every event
_TRUST_CACHE_MAX = 5000
_RDNS_TIMEOUT = 0.75              # seconds — keep the analysis worker from stalling on slow/absent DNS

def _trust(ip):
    if not isinstance(ip,str) or not ip: return 0.1,"unknown"
    if _is_private(ip): return 0.95, "private-network"
    cached = _TRUST_CACHE.get(ip)
    if cached is not None: return cached
    old_timeout = socket.getdefaulttimeout()
    result = (0.1, "unknown")
    try:
        socket.setdefaulttimeout(_RDNS_TIMEOUT)   # bound the blocking PTR lookup below
        h = socket.gethostbyaddr(ip)[0].lower()
        for d in _TRUSTED:
            if d in h: result = (0.8, d); break
        else:
            result = (0.4, h)
    except Exception:
        result = (0.1, "unknown")
    finally:
        socket.setdefaulttimeout(old_timeout)
    if len(_TRUST_CACHE) > _TRUST_CACHE_MAX: _TRUST_CACHE.clear()
    _TRUST_CACHE[ip] = result
    return result

class RiskResult:
    def __init__(self,**k):
        self.src_ip=k.get("src_ip",""); self.domain=k.get("domain","unknown")
        self.overall=k.get("overall",0.0); self.risk_score_100=k.get("risk_score_100",0.0)
        self.severity=k.get("severity","LOW"); self.signal_strength=k.get("signal_strength",0)
        self.signature_score=k.get("signature_score",0.0); self.anomaly_score=k.get("anomaly_score",0.0)
        self.temporal_density=k.get("temporal_density",0.0); self.behavioral_drift=k.get("behavioral_drift",0.0)
        self.packet_rate=k.get("packet_rate",0.0); self.trust_score=k.get("trust_score",0.1)
        self.mitre_boost=k.get("mitre_boost",0.0); self.asset_boost=k.get("asset_boost",0.0)
        self.response_action=k.get("response_action","Monitored")
        self.raw_components=k.get("raw_components",{})  # for adaptive_learning feedback

    def to_dict(self):
        return {
            "src_ip":self.src_ip,"domain":self.domain,
            "overall":round(self.overall,1),"risk_score":round(self.overall,1),
            "risk_score_100":round(self.risk_score_100,1),"severity":self.severity,
            "signal_strength":self.signal_strength,"signature_score":round(self.signature_score,3),
            "anomaly_score":round(self.anomaly_score,3),"temporal_density":round(self.temporal_density,1),
            "behavioral_drift":round(self.behavioral_drift,1),"packet_rate":round(self.packet_rate,1),
            "trust_score":round(self.trust_score,2),"mitre_boost":round(self.mitre_boost,1),
            "asset_boost":round(self.asset_boost,1),"response_action":self.response_action,
        }

class RiskEngine:
    ALPHA=0.40; BETA=0.30; GAMMA=0.20; DELTA=0.10

    def __init__(self):
        self._attack_hist=defaultdict(list); self._pkt_hist=defaultdict(list)
        self._pkt_ts=defaultdict(list); self._asset_mgr=None
        self._adaptive_learner=None   # injected via set_adaptive_learner()
        logger.info("RiskEngine ready (v4 multi-signal fusion)")

    def set_adaptive_learner(self, learner):
        """Inject the AdaptiveWeightLearner — once set, ALPHA/BETA/GAMMA/DELTA
        are replaced live by the learned weights on every evaluate() call."""
        self._adaptive_learner = learner

    def _current_weights(self):
        """Returns (ALPHA, BETA, GAMMA, DELTA) — adaptive if a learner is injected,
        otherwise the original hand-tuned defaults."""
        if self._adaptive_learner is not None:
            w = self._adaptive_learner.get_weights()
            return (w.get("signature",self.ALPHA), w.get("anomaly",self.BETA),
                    w.get("density",self.GAMMA), w.get("drift_rate",self.DELTA))
        return (self.ALPHA, self.BETA, self.GAMMA, self.DELTA)

    def set_asset_manager(self,am): self._asset_mgr=am

    def evaluate(self, det) -> RiskResult:
        if hasattr(det,"to_dict"):
            d=det.to_dict(); src_ip=getattr(det,"src_ip",""); dst_ip=getattr(det,"dst_ip","")
            attack_type=getattr(det,"attack_type","Normal"); confidence=_safe(getattr(det,"confidence",0.5))
            packet_count=_safe(d.get("packet_count",0)); unique_ports=_safe(d.get("unique_ports",0))
            syn_count=_safe(d.get("syn_count",0)); pps=_safe(d.get("pps",0))
            anomaly_flag=bool(d.get("anomaly_flag",False)); mitre_id=d.get("mitre_technique","")
        else:
            d=det if isinstance(det,dict) else {}
            src_ip=d.get("src_ip",""); dst_ip=d.get("dst_ip",""); attack_type=d.get("attack_type","Normal")
            confidence=_safe(d.get("confidence",0.5)); packet_count=_safe(d.get("packet_count",0))
            unique_ports=_safe(d.get("unique_ports",0)); syn_count=_safe(d.get("syn_count",0))
            pps=_safe(d.get("pps",0)); anomaly_flag=bool(d.get("anomaly_flag",False))
            mitre_id=d.get("mitre_technique","")
        src_ip=src_ip or "unknown"

        sig=confidence*100 if attack_type!="Normal" else 0.0
        anom=1.0 if anomaly_flag else 0.0
        rate=self._rate(src_ip); density=self._density(src_ip,attack_type); drift=self._drift(src_ip,packet_count)

        S=min(sig/100,1.0); A=anom; T=min(density/50,1.0); B=min(drift/500,1.0); R=min(rate/30,1.0)
        alpha,beta,gamma,delta=self._current_weights()
        risk=(alpha*S+beta*A+gamma*T+delta*(B+R))*100

        strength=sum([sig>20,bool(anomaly_flag),density>10,drift>20,rate>5])
        if   strength>=4: risk*=1.5
        elif strength>=3: risk*=1.2

        if unique_ports>10:  risk+=30
        if unique_ports>30:  risk+=50
        if syn_count>50:     risk+=40
        if rate>20:          risk+=30
        if pps>500:          risk+=20

        trust,domain=_trust(src_ip)
        # Private/local IPs: only flag if genuinely high signal strength
        if trust > 0.9:
            if strength < 2: return RiskResult(
                src_ip=src_ip, domain=domain, overall=0.0, risk_score_100=0.0,
                severity="LOW", signal_strength=0, signature_score=0.0,
                anomaly_score=0.0, temporal_density=0.0, behavioral_drift=0.0,
                packet_rate=rate, trust_score=trust, response_action="Ignored (local traffic)"
            )
            risk *= 0.4  # heavy discount — local IPs need much stronger signals
        elif trust > 0.7 and strength < 3:
            risk *= 0.5

        mb=0.0
        if mitre_id: mb=_MITRE_BOOST.get(mitre_id,_MITRE_BOOST.get(mitre_id[:5],0.0)); risk+=mb

        ab=0.0
        if self._asset_mgr:
            crit=self._asset_mgr.get_criticality(dst_ip)
            if crit: ab=(crit/10)*20; risk+=ab

        risk=max(0.0,min(100.0,_safe(risk)))
        sev=("CRITICAL" if risk>=85 else "HIGH" if risk>=50 else "MEDIUM" if risk>=20 else "LOW")
        resp=(f"AUTO-BLOCK risk={risk:.0f}" if risk>=90 else "Aggressive Monitoring" if risk>=50 else "Monitored")
        return RiskResult(
            src_ip=src_ip,domain=domain,overall=min(risk/10, 1.0),risk_score_100=min(risk,100),
            severity=sev,signal_strength=strength,signature_score=sig,anomaly_score=anom,
            temporal_density=density,behavioral_drift=drift,packet_rate=rate,
            trust_score=trust,mitre_boost=mb,asset_boost=ab,response_action=resp,
            raw_components={"signature":S,"anomaly":A,"density":T,"drift_rate":B+R},
        )

    def _rate(self,ip):
        now=time.time(); self._pkt_ts[ip].append(now)
        self._pkt_ts[ip]=[t for t in self._pkt_ts[ip] if now-t<=30]
        return float(len(self._pkt_ts[ip]))

    def _density(self,ip,attack):
        if attack=="Normal": return 0.0
        now=time.time(); self._attack_hist[ip].append(now)
        self._attack_hist[ip]=[t for t in self._attack_hist[ip] if now-t<=60]
        return float(len(self._attack_hist[ip]))

    def _drift(self,ip,cnt):
        h=self._pkt_hist[ip]; h.append(cnt)
        if len(h)>20: h.pop(0)
        if len(h)<5: return 0.0
        avg=sum(h[:-1])/(len(h)-1); return abs(cnt-avg)

# Alias: RiskScore is the same as RiskResult.
# The __init__.py and event_manager.py reference RiskScore by name;
# RiskResult was renamed at some point but the alias was never added.
RiskScore = RiskResult
