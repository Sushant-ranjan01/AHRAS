"""AHRAS v5 multi-signal risk engine with continuous anomaly evidence."""
from __future__ import annotations

import math
import socket
import time
import logging
from collections import defaultdict

logger = logging.getLogger("ahras.risk")

_TRUSTED = ["google", "amazonaws", "cloudflare", "microsoft", "facebook", "akamai", "fastly", "apple", "github"]
_MITRE_BOOST = {"T1486": 25, "T1041": 20, "T1021": 18, "T1095": 15, "T1071": 12, "T1110": 10, "T1190": 15, "T1498": 8, "T1046": 5}


def _safe(v, d=0.0):
    if v is None:
        return d
    try:
        x = float(v)
    except (TypeError, ValueError):
        return d
    return x if math.isfinite(x) else d


def _is_private(ip: str) -> bool:
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return False
        a, b = parts[0], parts[1]
        return a == 10 or a == 127 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 169 and b == 254)
    except Exception:
        return False


_TRUST_CACHE = {}
_TRUST_CACHE_MAX = 5000
_RDNS_TIMEOUT = 0.75


def _trust(ip, skip_dns=False):
    if not isinstance(ip, str) or not ip:
        return 0.1, "unknown"
    if _is_private(ip):
        return 0.95, "private-network"
    if ip in _TRUST_CACHE:
        return _TRUST_CACHE[ip]
    if skip_dns:
        result = (0.1, "unknown")
    else:
        old_timeout = socket.getdefaulttimeout()
        result = (0.1, "unknown")
        try:
            socket.setdefaulttimeout(_RDNS_TIMEOUT)
            hostname = socket.gethostbyaddr(ip)[0].lower()
            result = (0.8, next((d for d in _TRUSTED if d in hostname), None))
            if result[1] is None:
                result = (0.4, hostname)
        except Exception:
            pass
        finally:
            socket.setdefaulttimeout(old_timeout)
    if len(_TRUST_CACHE) > _TRUST_CACHE_MAX:
        _TRUST_CACHE.clear()
    _TRUST_CACHE[ip] = result
    return result


class RiskResult:
    def __init__(self, **k):
        self.src_ip = k.get("src_ip", "")
        self.domain = k.get("domain", "unknown")
        self.overall = k.get("overall", 0.0)
        self.risk_score_100 = k.get("risk_score_100", 0.0)
        self.severity = k.get("severity", "LOW")
        self.signal_strength = k.get("signal_strength", 0)
        self.signature_score = k.get("signature_score", 0.0)
        self.anomaly_score = k.get("anomaly_score", 0.0)
        self.anomaly_flag = k.get("anomaly_flag", False)
        self.temporal_density = k.get("temporal_density", 0.0)
        self.behavioral_drift = k.get("behavioral_drift", 0.0)
        self.packet_rate = k.get("packet_rate", 0.0)
        self.trust_score = k.get("trust_score", 0.1)
        self.mitre_boost = k.get("mitre_boost", 0.0)
        self.asset_boost = k.get("asset_boost", 0.0)
        self.history_boost = k.get("history_boost", 0.0)
        self.response_action = k.get("response_action", "Monitored")
        self.raw_components = k.get("raw_components", {})

    def to_dict(self):
        return {
            "src_ip": self.src_ip,
            "domain": self.domain,
            "overall": round(self.overall, 3),
            "risk_score": round(self.overall, 1),
            "risk_score_100": round(self.risk_score_100, 2),
            "severity": self.severity,
            "signal_strength": self.signal_strength,
            "signature_score": round(self.signature_score, 3),
            "anomaly_score": round(self.anomaly_score, 3),
            "anomaly_flag": self.anomaly_flag,
            "temporal_density": round(self.temporal_density, 3),
            "behavioral_drift": round(self.behavioral_drift, 3),
            "packet_rate": round(self.packet_rate, 3),
            "trust_score": round(self.trust_score, 3),
            "mitre_boost": round(self.mitre_boost, 3),
            "asset_boost": round(self.asset_boost, 3),
            "history_boost": round(self.history_boost, 3),
            "response_action": self.response_action,
            "raw_components": self.raw_components,
        }


class RiskEngine:
    ALPHA = 0.40
    BETA = 0.30
    GAMMA = 0.20
    DELTA = 0.10

    def __init__(self, skip_dns=False):
        self._attack_hist = defaultdict(list)
        self._pkt_hist = defaultdict(list)
        self._pkt_ts = defaultdict(list)
        self._asset_mgr = None
        self._adaptive_learner = None
        self._skip_dns = skip_dns
        logger.info("RiskEngine ready (v5 multi-signal fusion)%s", " [skip_dns]" if skip_dns else "")

    def set_adaptive_learner(self, learner):
        self._adaptive_learner = learner

    def _current_weights(self):
        if self._adaptive_learner is not None:
            w = self._adaptive_learner.get_weights()
            return (
                w.get("signature", self.ALPHA),
                w.get("anomaly", self.BETA),
                w.get("density", self.GAMMA),
                w.get("drift_rate", self.DELTA),
            )
        return self.ALPHA, self.BETA, self.GAMMA, self.DELTA

    def set_asset_manager(self, am):
        self._asset_mgr = am

    def evaluate(self, det) -> RiskResult:
        if hasattr(det, "to_dict"):
            d = det.to_dict()
            src_ip = getattr(det, "src_ip", d.get("src_ip", ""))
            dst_ip = getattr(det, "dst_ip", d.get("dst_ip", ""))
            attack_type = getattr(det, "attack_type", d.get("attack_type", "Normal"))
            confidence = _safe(getattr(det, "confidence", d.get("confidence", 0.5)), 0.5)
            signature_confidence = _safe(getattr(det, "signature_confidence", d.get("signature_confidence", confidence)), 0.0)
            continuous_anomaly = _safe(getattr(det, "anomaly_score", d.get("anomaly_score", 0.0)), 0.0)
            anomaly_flag = bool(getattr(det, "anomaly_result", None) and getattr(det.anomaly_result, "is_anomaly", False))
            if "anomaly_score" in d:
                continuous_anomaly = _safe(d.get("anomaly_score"), continuous_anomaly)
            packet_count = _safe(d.get("packet_count", 0))
            unique_ports = _safe(d.get("unique_ports", 0))
            syn_count = _safe(d.get("syn_count", 0))
            pps = _safe(d.get("pps", 0))
            event_time = d.get("event_time")
            history_boost = _safe(d.get("history_boost", getattr(det, "history_boost", 0.0)))
            bytes_per_sec = _safe(d.get("bytes_per_sec", 0.0))
        else:
            d = det if isinstance(det, dict) else {}
            src_ip = d.get("src_ip", "")
            dst_ip = d.get("dst_ip", "")
            attack_type = d.get("attack_type", "Normal")
            confidence = _safe(d.get("confidence", 0.5), 0.5)
            signature_confidence = _safe(d.get("signature_confidence", confidence), 0.0)
            continuous_anomaly = _safe(d.get("anomaly_score", 0.0), 0.0)
            anomaly_flag = bool(d.get("anomaly_flag", False))
            packet_count = _safe(d.get("packet_count", 0))
            unique_ports = _safe(d.get("unique_ports", 0))
            syn_count = _safe(d.get("syn_count", 0))
            pps = _safe(d.get("pps", 0))
            event_time = d.get("event_time")
            history_boost = _safe(d.get("history_boost", 0.0))
            bytes_per_sec = _safe(d.get("bytes_per_sec", 0.0))

        src_ip = src_ip or "unknown"
        history_boost = max(0.0, min(45.0, history_boost))
        signature_signal = signature_confidence if attack_type != "Normal" else 0.0
        anomaly_signal = max(0.0, min(1.0, continuous_anomaly))
        if anomaly_signal <= 0 and anomaly_flag:
            anomaly_signal = 1.0

        rate = self._rate(src_ip, now=event_time)
        density = self._density(src_ip, attack_type, now=event_time)
        drift = self._drift(src_ip, packet_count)

        S = max(0.0, min(signature_signal, 1.0))
        A = anomaly_signal
        T = min(density / 50.0, 1.0)
        B = min(drift / 500.0, 1.0)
        R = min(rate / 30.0, 1.0)
        alpha, beta, gamma, delta = self._current_weights()
        base_risk = (alpha * S + beta * A + gamma * T + delta * (B + R)) * 100.0
        risk = base_risk

        strength = sum([S > 0.20, A > 0.50, density > 10, drift > 20, rate > 5])
        strength_mult = 1.5 if strength >= 4 else 1.2 if strength >= 3 else 1.0
        risk *= strength_mult
        risk_after_strength = risk

        rule_boosts = []
        if unique_ports > 10:
            rule_boosts.append(("unique_ports>10", 30.0))
        if unique_ports > 30:
            rule_boosts.append(("unique_ports>30", 50.0))
        if syn_count > 50:
            rule_boosts.append(("syn_count>50", 40.0))
        if rate > 20 and packet_count >= 20:
            rule_boosts.append(("rate>20_and_packet_count>=20", 30.0))
        if pps > 500 and packet_count >= 20:
            rule_boosts.append(("pps>500_and_packet_count>=20", 20.0))
        rule_boost_total = sum(v for _, v in rule_boosts)
        risk += rule_boost_total
        risk_after_rules = risk

        trust, domain = _trust(src_ip, skip_dns=self._skip_dns)
        trust_adjustment = {"type": "none", "factor": 1.0}
        if trust > 0.9:
            if strength < 2:
                return RiskResult(
                    src_ip=src_ip, domain=domain, overall=0.0, risk_score_100=0.0,
                    severity="LOW", signal_strength=0, signature_score=0.0,
                    anomaly_score=anomaly_signal, anomaly_flag=anomaly_flag,
                    temporal_density=0.0, behavioral_drift=0.0, packet_rate=rate,
                    trust_score=trust, response_action="Ignored (local traffic)",
                    raw_components={
                        "signature": S, "anomaly": A, "density": T, "drift_rate": B + R,
                        "weights_used": {"signature": alpha, "anomaly": beta, "density": gamma, "drift_rate": delta},
                        "base_risk": round(base_risk, 2), "strength": strength,
                        "strength_multiplier": 1.0, "risk_after_strength": round(base_risk, 2),
                        "rule_boosts": [], "rule_boost_total": 0.0,
                        "risk_after_rules": round(base_risk, 2),
                        "trust_adjustment": {"type": "trusted_local_ignored", "factor": 0.0},
                        "risk_after_trust": 0.0, "mitre_boost": 0.0, "asset_boost": 0.0,
                        "history_boost": 0.0, "pre_cap_risk": 0.0, "capped": False,
                    },
                )
            risk *= 0.4
            trust_adjustment = {"type": "trusted_local_discount", "factor": 0.4}
        elif trust > 0.7 and strength < 3:
            risk *= 0.5
            trust_adjustment = {"type": "trusted_domain_discount", "factor": 0.5}
        risk_after_trust = risk

        mitre_id = d.get("mitre_technique", "")
        mb = _MITRE_BOOST.get(mitre_id, _MITRE_BOOST.get(str(mitre_id)[:5], 0.0)) if mitre_id else 0.0
        risk += mb

        ab = 0.0
        if self._asset_mgr:
            crit = self._asset_mgr.get_criticality(dst_ip)
            if crit:
                ab = (crit / 10.0) * 20.0
                risk += ab

        risk += history_boost
        pre_cap_risk = risk
        risk = max(0.0, min(100.0, _safe(risk)))
        capped = pre_cap_risk > 100.0 or pre_cap_risk < 0.0
        severity = "CRITICAL" if risk >= 85 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 20 else "LOW"
        response = f"AUTO-BLOCK risk={risk:.0f}" if risk >= 90 else "Aggressive Monitoring" if risk >= 50 else "Monitored"

        return RiskResult(
            src_ip=src_ip,
            domain=domain,
            overall=min(risk / 10.0, 1.0),
            risk_score_100=min(risk, 100.0),
            severity=severity,
            signal_strength=strength,
            signature_score=S,
            anomaly_score=A,
            anomaly_flag=anomaly_flag,
            temporal_density=density,
            behavioral_drift=drift,
            packet_rate=rate,
            trust_score=trust,
            mitre_boost=mb,
            asset_boost=ab,
            history_boost=history_boost,
            response_action=response,
            raw_components={
                "signature": S,
                "anomaly": A,
                "density": T,
                "drift_rate": B + R,
                "weights_used": {"signature": alpha, "anomaly": beta, "density": gamma, "drift_rate": delta},
                "base_risk": round(base_risk, 2),
                "strength": strength,
                "strength_multiplier": strength_mult,
                "risk_after_strength": round(risk_after_strength, 2),
                "rule_boosts": [{"rule": n, "points": v} for n, v in rule_boosts],
                "rule_boost_total": round(rule_boost_total, 2),
                "risk_after_rules": round(risk_after_rules, 2),
                "trust_adjustment": trust_adjustment,
                "risk_after_trust": round(risk_after_trust, 2),
                "mitre_boost": round(mb, 2),
                "asset_boost": round(ab, 2),
                "history_boost": round(history_boost, 2),
                "pre_cap_risk": round(pre_cap_risk, 2),
                "capped": capped,
            },
        )

    def _rate(self, ip, now=None):
        now = _safe(now, time.time())
        self._pkt_ts[ip].append(now)
        self._pkt_ts[ip] = [t for t in self._pkt_ts[ip] if 0 <= now - t <= 30]
        return float(len(self._pkt_ts[ip]))

    def _density(self, ip, attack, now=None):
        if attack == "Normal":
            return 0.0
        now = _safe(now, time.time())
        self._attack_hist[ip].append(now)
        self._attack_hist[ip] = [t for t in self._attack_hist[ip] if 0 <= now - t <= 60]
        return float(len(self._attack_hist[ip]))

    def _drift(self, ip, cnt):
        h = self._pkt_hist[ip]
        h.append(cnt)
        if len(h) > 20:
            h.pop(0)
        if len(h) < 5:
            return 0.0
        avg = sum(h[:-1]) / max(len(h) - 1, 1)
        return abs(cnt - avg)


RiskScore = RiskResult