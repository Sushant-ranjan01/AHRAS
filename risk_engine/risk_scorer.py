"""
AHRAS v5.0 — Advanced Risk Engine

Merges working version's multi-signal weighted fusion
WITH v3 MITRE boosts + asset criticality.

Risk Formula:

R = (α·Sig + β·Anomaly + γ·Density + δ·(Drift+Rate)) * 100

* signal-strength multiplier

+ behavioral rule boosts (ports/syn/rate/pps)

(× trust discount, or short-circuit to 0 for trusted/low-signal local traffic)

+ MITRE severity boost
+ Asset criticality boost
+ Historical-recidivism boost

capped to [0, 100]

Every term above is recorded verbatim in RiskResult.raw_components
so that risk_explainer.RiskExplainer can reconstruct the score EXACTLY
(not re-derive it from a different formula) — see
risk_explainer/explainer.py for the "faithful-by-construction"
XAI design this enables.


── Architecture decision: which modules feed the per-event score ───────────

Only FOUR sources are treated as formal risk-score INPUTS:

1. the four weighted base signals
   (signature / anomaly / density / drift+rate)

2. rule-based / MITRE / asset-criticality boosts
   (deterministic, per-event)

3. trust (reverse-DNS reputation) discount

4. historical recidivism boost
   (historical_risk.HistoricalRiskEngine.get_boost)
   — keyed on the SAME src_ip as this event, computed from that IP's PAST
   events only (recorded to history strictly after scoring — see main.py's
   analysis worker), so folding it in here is a simple, non-circular,
   well-defined additive term.


UBA, the correlation/threat-graph, and the attack forecaster are
deliberately kept OUT of this per-event formula and treated as auxiliary /
contextual modules instead, for two concrete reasons:

- UBA operates on a different entity/event stream
  (authenticated username logins) than RiskEngine
  (network flow src_ip/dst_ip detections). There
  is no reliable 1:1 join key between "this flow" and "this login"
  in the current data model, so any wiring would be a guess,
  not a signal.

- The threat graph and the attack forecaster are BUILT FROM already-scored
  events (graph.ingest_event / forecast trains on hist_risk's risk
  series). Feeding their output back into the score that produced them
  creates a circular dependency and risks a feedback loop
  (rising forecast → higher score → higher forecast → ...).
  Historical risk avoids this because it is a simple counter of past
  occurrences, not a model trained on past scores.

This split is intentional and is what item 6 of the v5 architecture review
formalizes; see also risk_explainer.explainer for how it's surfaced to
analysts (weighted components vs. contextual signals).
"""

import time
import socket
import logging

from collections import defaultdict


logger = logging.getLogger("ahras.risk")


# ============================================================
# TRUSTED DOMAINS
# ============================================================

_TRUSTED = [
    "google",
    "amazonaws",
    "cloudflare",
    "microsoft",
    "facebook",
    "akamai",
    "fastly",
    "apple",
    "github"
]


# ============================================================
# MITRE BOOST VALUES
# ============================================================

_MITRE_BOOST = {
    "T1486": 25,
    "T1041": 20,
    "T1021": 18,
    "T1095": 15,
    "T1071": 12,
    "T1110": 10,
    "T1190": 15,
    "T1498": 8,
    "T1046": 5,
}


# ============================================================
# SAFE VALUE CONVERSION
# ============================================================

def _safe(v, d=0.0):

    if v is None:
        return d

    if isinstance(v, (int, float)):
        return float(v)

    try:
        return float(v)

    except Exception:
        return d


# ============================================================
# PRIVATE IP CHECK
# ============================================================

def _is_private(ip: str):
    """
    Return True for RFC-1918 / loopback / link-local addresses.
    """

    try:

        parts = [int(x) for x in ip.split(".")]

        if len(parts) != 4:
            return False

        a, b = parts[0], parts[1]

        return (
            a == 10
            or a == 127
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or (a == 169 and b == 254)
        )

    except Exception:

        return False


# ============================================================
# TRUST CACHE
# ============================================================

_TRUST_CACHE: dict = {}

# ip -> (trust, domain)
# avoids re-resolving on every event

_TRUST_CACHE_MAX = 5000

# seconds — keep the analysis worker from stalling
# on slow/absent DNS

_RDNS_TIMEOUT = 0.75


# ============================================================
# TRUST FUNCTION
# ============================================================

def _trust(ip, skip_dns=False):
    """
    skip_dns=True bypasses the blocking reverse-DNS lookup entirely
    and returns the same fallback ("unknown", trust=0.1)
    that a failed/timed-out lookup would have produced anyway.

    This matters for BULK dataset evaluation
    (thousands of unique synthetic/attacker source IPs,
    almost none with real PTR records):

    at 0.75s per unique IP, a 20k-row CICIDS file with
    e.g. 5,000 distinct IPs costs ~62 minutes of pure
    DNS-timeout stalling for a result that was going
    to be "unknown" anyway.

    Live production traffic should NOT set this —
    real IPs do sometimes resolve to a trusted domain,
    and that signal matters there.
    """

    if not isinstance(ip, str) or not ip:

        return 0.1, "unknown"

    # Private/local network
    if _is_private(ip):

        return 0.95, "private-network"

    # Check cache
    cached = _TRUST_CACHE.get(ip)

    if cached is not None:

        return cached

    # Bulk evaluation mode
    if skip_dns:

        result = (
            0.1,
            "unknown"
        )

        if len(_TRUST_CACHE) > _TRUST_CACHE_MAX:

            _TRUST_CACHE.clear()

        _TRUST_CACHE[ip] = result

        return result

    old_timeout = socket.getdefaulttimeout()

    result = (
        0.1,
        "unknown"
    )

    try:

        socket.setdefaulttimeout(
            _RDNS_TIMEOUT
        )

        h = socket.gethostbyaddr(
            ip
        )[0].lower()

        for d in _TRUSTED:

            if d in h:

                result = (
                    0.8,
                    d
                )

                break

        else:

            result = (
                0.4,
                h
            )

    except Exception:

        result = (
            0.1,
            "unknown"
        )

    finally:

        socket.setdefaulttimeout(
            old_timeout
        )

    if len(_TRUST_CACHE) > _TRUST_CACHE_MAX:

        _TRUST_CACHE.clear()

    _TRUST_CACHE[ip] = result

    return result


# ============================================================
# RISK RESULT
# ============================================================

class RiskResult:

    def __init__(self, **k):

        self.src_ip = k.get(
            "src_ip",
            ""
        )

        self.domain = k.get(
            "domain",
            "unknown"
        )

        self.overall = k.get(
            "overall",
            0.0
        )

        self.risk_score_100 = k.get(
            "risk_score_100",
            0.0
        )

        self.severity = k.get(
            "severity",
            "LOW"
        )

        self.signal_strength = k.get(
            "signal_strength",
            0
        )

        self.signature_score = k.get(
            "signature_score",
            0.0
        )

        self.anomaly_score = k.get(
            "anomaly_score",
            0.0
        )

        self.temporal_density = k.get(
            "temporal_density",
            0.0
        )

        self.behavioral_drift = k.get(
            "behavioral_drift",
            0.0
        )

        self.packet_rate = k.get(
            "packet_rate",
            0.0
        )

        self.trust_score = k.get(
            "trust_score",
            0.1
        )

        self.mitre_boost = k.get(
            "mitre_boost",
            0.0
        )

        self.asset_boost = k.get(
            "asset_boost",
            0.0
        )

        self.history_boost = k.get(
            "history_boost",
            0.0
        )

        self.response_action = k.get(
            "response_action",
            "Monitored"
        )

        # for adaptive_learning feedback
        # + RiskExplainer
        self.raw_components = k.get(
            "raw_components",
            {}
        )

    # ========================================================
    # CONVERT RESULT TO DICTIONARY
    # ========================================================

    def to_dict(self):

        return {

            "src_ip": self.src_ip,

            "domain": self.domain,

            "overall": round(
                self.overall,
                1
            ),

            "risk_score": round(
                self.overall,
                1
            ),

            "risk_score_100": round(
                self.risk_score_100,
                1
            ),

            "severity": self.severity,

            "signal_strength": self.signal_strength,

            "signature_score": round(
                self.signature_score,
                3
            ),

            "anomaly_score": round(
                self.anomaly_score,
                3
            ),

            "temporal_density": round(
                self.temporal_density,
                1
            ),

            "behavioral_drift": round(
                self.behavioral_drift,
                1
            ),

            "packet_rate": round(
                self.packet_rate,
                1
            ),

            "trust_score": round(
                self.trust_score,
                2
            ),

            "mitre_boost": round(
                self.mitre_boost,
                1
            ),

            "asset_boost": round(
                self.asset_boost,
                1
            ),

            "history_boost": round(
                self.history_boost,
                1
            ),

            "response_action":
                self.response_action,

        }


# ============================================================
# RISK ENGINE
# ============================================================

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

        # injected via set_adaptive_learner()
        self._adaptive_learner = None

        # bulk-evaluation mode
        # — see _trust() docstring
        self._skip_dns = skip_dns

        logger.info(
            "RiskEngine ready (v4 multi-signal fusion)"
            + (
                " [skip_dns]"
                if skip_dns
                else ""
            )
        )

    # ========================================================
    # SET ADAPTIVE LEARNER
    # ========================================================

    def set_adaptive_learner(self, learner):
        """
        Inject the AdaptiveWeightLearner.

        Once set, ALPHA/BETA/GAMMA/DELTA
        are replaced live by the learned weights
        on every evaluate() call.
        """

        self._adaptive_learner = learner

    # ========================================================
    # CURRENT WEIGHTS
    # ========================================================

    def _current_weights(self):
        """
        Returns (ALPHA, BETA, GAMMA, DELTA)
        — adaptive if a learner is injected,
        otherwise the original hand-tuned defaults.
        """

        if self._adaptive_learner is not None:

            w = self._adaptive_learner.get_weights()

            return (
                w.get(
                    "signature",
                    self.ALPHA
                ),

                w.get(
                    "anomaly",
                    self.BETA
                ),

                w.get(
                    "density",
                    self.GAMMA
                ),

                w.get(
                    "drift_rate",
                    self.DELTA
                )
            )

        return (
            self.ALPHA,
            self.BETA,
            self.GAMMA,
            self.DELTA
        )

    # ========================================================
    # SET ASSET MANAGER
    # ========================================================

    def set_asset_manager(self, am):

        self._asset_mgr = am

    # ========================================================
    # MAIN EVALUATION
    # ========================================================

    def evaluate(self, det) -> RiskResult:

        if hasattr(det, "to_dict"):

            d = det.to_dict()

            src_ip = getattr(
                det,
                "src_ip",
                ""
            )

            dst_ip = getattr(
                det,
                "dst_ip",
                ""
            )

            attack_type = getattr(
                det,
                "attack_type",
                "Normal"
            )

            confidence = _safe(
                getattr(
                    det,
                    "confidence",
                    0.5
                )
            )

            packet_count = _safe(
                d.get(
                    "packet_count",
                    0
                )
            )

            unique_ports = _safe(
                d.get(
                    "unique_ports",
                    0
                )
            )

            syn_count = _safe(
                d.get(
                    "syn_count",
                    0
                )
            )

            pps = _safe(
                d.get(
                    "pps",
                    0
                )
            )

            anomaly_flag = bool(
                d.get(
                    "anomaly_flag",
                    False
                )
            )

            mitre_id = d.get(
                "mitre_technique",
                ""
            )

            event_time = d.get(
                "event_time"
            )

            # history_boost: set externally by the analysis worker via
            # `det.history_boost = hist_risk.get_boost(src_ip)` BEFORE this
            # event is recorded into history (see main.py) — non-circular,
            # see module docstring.

            history_boost = _safe(
                getattr(
                    det,
                    "history_boost",
                    d.get(
                        "history_boost",
                        0.0
                    )
                )
            )

        else:

            d = (
                det
                if isinstance(det, dict)
                else {}
            )

            src_ip = d.get(
                "src_ip",
                ""
            )

            dst_ip = d.get(
                "dst_ip",
                ""
            )

            attack_type = d.get(
                "attack_type",
                "Normal"
            )

            confidence = _safe(
                d.get(
                    "confidence",
                    0.5
                )
            )

            packet_count = _safe(
                d.get(
                    "packet_count",
                    0
                )
            )

            unique_ports = _safe(
                d.get(
                    "unique_ports",
                    0
                )
            )

            syn_count = _safe(
                d.get(
                    "syn_count",
                    0
                )
            )

            pps = _safe(
                d.get(
                    "pps",
                    0
                )
            )

            anomaly_flag = bool(
                d.get(
                    "anomaly_flag",
                    False
                )
            )

            mitre_id = d.get(
                "mitre_technique",
                ""
            )

            event_time = d.get(
                "event_time"
            )

            history_boost = _safe(
                d.get(
                    "history_boost",
                    0.0
                )
            )

        src_ip = src_ip or "unknown"

        # matches HistoricalRiskEngine's own cap
        # (30+15)

        history_boost = max(
            0.0,
            min(
                45.0,
                history_boost
            )
        )

        # ====================================================
        # BASE SIGNALS
        # ====================================================

        sig = (
            confidence * 100
            if attack_type != "Normal"
            else 0.0
        )

        anom = (
            1.0
            if anomaly_flag
            else 0.0
        )

        rate = self._rate(
            src_ip,
            now=event_time
        )

        density = self._density(
            src_ip,
            attack_type,
            now=event_time
        )

        drift = self._drift(
            src_ip,
            packet_count
        )

        # ====================================================
        # NORMALIZATION
        # ====================================================

        S = min(
            sig / 100,
            1.0
        )

        A = anom

        T = min(
            density / 50,
            1.0
        )

        B = min(
            drift / 500,
            1.0
        )

        R = min(
            rate / 30,
            1.0
        )

        alpha, beta, gamma, delta = (
            self._current_weights()
        )

        # ====================================================
        # BASE RISK
        # ====================================================

        base_risk = (
            alpha * S
            + beta * A
            + gamma * T
            + delta * (B + R)
        ) * 100

        risk = base_risk

        # ====================================================
        # SIGNAL STRENGTH
        # ====================================================

        strength = sum([
            sig > 20,
            bool(anomaly_flag),
            density > 10,
            drift > 20,
            rate > 5
        ])

        strength_mult = (
            1.5
            if strength >= 4
            else 1.2
            if strength >= 3
            else 1.0
        )

        risk *= strength_mult

        risk_after_strength = risk

        # ====================================================
        # BEHAVIORAL RULE BOOSTS
        # ====================================================

        # BUG FIX: pps ("Flow Packets/s") is packet_count / flow_duration.
        # For very short flows (a handful of packets over a few
        # microseconds -- an ordinary handshake, ACK, or quick DNS lookup)
        # this ratio blows up to hundreds of thousands or millions,
        # mathematically, with nothing resembling a real burst underneath
        # it. Confirmed on real CICIDS2017 traffic: 100% of false positives
        # on a zero-attack day (Monday) were caused by this single rule
        # firing on ordinary short benign flows with pps values like
        # 2,000,000 -- no real flood sustains that. A genuine high-rate
        # attack has BOTH a high computed rate AND an actual volume of
        # packets; requiring packet_count as well filters out the
        # short-flow division artifact while still catching real floods
        # (which have far more than a couple dozen packets).

        rule_boosts = []

        if unique_ports > 10:

            rule_boosts.append(
                (
                    "unique_ports>10",
                    30.0
                )
            )

        if unique_ports > 30:

            rule_boosts.append(
                (
                    "unique_ports>30",
                    50.0
                )
            )

        if syn_count > 50:

            rule_boosts.append(
                (
                    "syn_count>50",
                    40.0
                )
            )

        if rate > 20:

            rule_boosts.append(
                (
                    "rate>20",
                    30.0
                )
            )

        if (
            pps > 500
            and packet_count >= 20
        ):

            rule_boosts.append(
                (
                    "pps>500_and_packet_count>=20",
                    20.0
                )
            )

        rule_boost_total = sum(
            value
            for _, value
            in rule_boosts
        )

        risk += rule_boost_total

        risk_after_rules = risk

        # ====================================================
        # TRUST
        # ====================================================

        trust, domain = _trust(
            src_ip,
            skip_dns=self._skip_dns
        )

        trust_adjustment = {
            "type": "none",
            "factor": 1.0
        }

        # Private/local IPs:
        # only flag if genuinely high signal strength

        if trust > 0.9:

            if strength < 2:

                return RiskResult(

                    src_ip=src_ip,

                    domain=domain,

                    overall=0.0,

                    risk_score_100=0.0,

                    severity="LOW",

                    signal_strength=0,

                    signature_score=0.0,

                    anomaly_score=0.0,

                    temporal_density=0.0,

                    behavioral_drift=0.0,

                    packet_rate=rate,

                    trust_score=trust,

                    response_action=
                        "Ignored (local traffic)",

                    raw_components={

                        "signature": S,

                        "anomaly": A,

                        "density": T,

                        "drift_rate": B + R,

                        "weights_used": {

                            "signature": alpha,

                            "anomaly": beta,

                            "density": gamma,

                            "drift_rate": delta
                        },

                        "base_risk":
                            round(
                                base_risk,
                                2
                            ),

                        "strength": strength,

                        "strength_multiplier": 1.0,

                        "risk_after_strength":
                            round(
                                base_risk,
                                2
                            ),

                        "rule_boosts": [],

                        "rule_boost_total": 0.0,

                        "risk_after_rules":
                            round(
                                base_risk,
                                2
                            ),

                        "trust_adjustment": {

                            "type":
                                "trusted_local_ignored",

                            "factor": 0.0
                        },

                        "risk_after_trust": 0.0,

                        "mitre_boost": 0.0,

                        "asset_boost": 0.0,

                        "history_boost": 0.0,

                        "pre_cap_risk": 0.0,

                        "capped": False
                    }
                )

            # Heavy discount —
            # local IPs need much stronger signals

            risk *= 0.4

            trust_adjustment = {

                "type":
                    "trusted_local_discount",

                "factor": 0.4
            }

        elif trust > 0.7 and strength < 3:

            risk *= 0.5

            trust_adjustment = {

                "type":
                    "trusted_domain_discount",

                "factor": 0.5
            }

        risk_after_trust = risk

        # ====================================================
        # MITRE BOOST
        # ====================================================

        mb = 0.0

        if mitre_id:

            mb = _MITRE_BOOST.get(
                mitre_id,
                _MITRE_BOOST.get(
                    mitre_id[:5],
                    0.0
                )
            )

            risk += mb

        # ====================================================
        # ASSET CRITICALITY BOOST
        # ====================================================

        ab = 0.0

        if self._asset_mgr:

            crit = self._asset_mgr.get_criticality(
                dst_ip
            )

            if crit:

                ab = (
                    crit / 10
                ) * 20

                risk += ab

        # ====================================================
        # HISTORICAL RECIDIVISM BOOST
        # ====================================================

        # Historical recidivism boost —
        # see module docstring for why this
        # (and only this) auxiliary signal
        # is wired directly into the score.

        risk += history_boost

        # ====================================================
        # FINAL CAP
        # ====================================================

        pre_cap_risk = risk

        risk = max(
            0.0,
            min(
                100.0,
                _safe(risk)
            )
        )

        capped = (
            pre_cap_risk > 100.0
            or pre_cap_risk < 0.0
        )

        # ====================================================
        # SEVERITY
        # ====================================================

        sev = (
            "CRITICAL"
            if risk >= 85
            else "HIGH"
            if risk >= 50
            else "MEDIUM"
            if risk >= 20
            else "LOW"
        )

        # ====================================================
        # RESPONSE ACTION
        # ====================================================

        resp = (
            f"AUTO-BLOCK risk={risk:.0f}"
            if risk >= 90
            else
            "Aggressive Monitoring"
            if risk >= 50
            else
            "Monitored"
        )

        # ====================================================
        # FINAL RISK RESULT
        # ====================================================

        return RiskResult(

            src_ip=src_ip,

            domain=domain,

            overall=min(
                risk / 10,
                1.0
            ),

            risk_score_100=min(
                risk,
                100
            ),

            severity=sev,

            signal_strength=strength,

            signature_score=sig,

            anomaly_score=anom,

            temporal_density=density,

            behavioral_drift=drift,

            packet_rate=rate,

            trust_score=trust,

            mitre_boost=mb,

            asset_boost=ab,

            history_boost=history_boost,

            response_action=resp,

            raw_components={

                "signature": S,

                "anomaly": A,

                "density": T,

                "drift_rate": B + R,

                "weights_used": {

                    "signature": alpha,

                    "anomaly": beta,

                    "density": gamma,

                    "drift_rate": delta
                },

                "base_risk":
                    round(
                        base_risk,
                        2
                    ),

                "strength": strength,

                "strength_multiplier":
                    strength_mult,

                "risk_after_strength":
                    round(
                        risk_after_strength,
                        2
                    ),

                "rule_boosts": [

                    {
                        "rule": name,
                        "points": value
                    }

                    for name, value
                    in rule_boosts
                ],

                "rule_boost_total":
                    round(
                        rule_boost_total,
                        2
                    ),

                "risk_after_rules":
                    round(
                        risk_after_rules,
                        2
                    ),

                "trust_adjustment":
                    trust_adjustment,

                "risk_after_trust":
                    round(
                        risk_after_trust,
                        2
                    ),

                "mitre_boost":
                    round(
                        mb,
                        2
                    ),

                "asset_boost":
                    round(
                        ab,
                        2
                    ),

                "history_boost":
                    round(
                        history_boost,
                        2
                    ),

                "pre_cap_risk":
                    round(
                        pre_cap_risk,
                        2
                    ),

                "capped": capped
            }
        )

    # ========================================================
    # PACKET RATE
    # ========================================================

    def _rate(self, ip, now=None):

        # `now` lets bulk dataset evaluation pass
        # the dataset's OWN row timestamp instead of
        # wall-clock time.time().

        # Without this, replaying a whole day's traffic
        # in under a second makes every IP that appears
        # more than ~20-30 times anywhere in the file look
        # like it's "bursting 30 packets in 30 real seconds"
        # -- a batch-replay artifact, not real bursty behavior.

        # Live production traffic (now=None) is
        # completely unaffected: falls straight through
        # to time.time() as before.

        now = (
            now
            if now is not None
            else time.time()
        )

        self._pkt_ts[ip].append(now)

        self._pkt_ts[ip] = [
            t
            for t in self._pkt_ts[ip]
            if now - t <= 30
        ]

        return float(
            len(
                self._pkt_ts[ip]
            )
        )

    # ========================================================
    # TEMPORAL DENSITY
    # ========================================================

    def _density(
        self,
        ip,
        attack,
        now=None
    ):

        if attack == "Normal":

            return 0.0

        now = (
            now
            if now is not None
            else time.time()
        )

        self._attack_hist[ip].append(now)

        self._attack_hist[ip] = [
            t
            for t in self._attack_hist[ip]
            if now - t <= 60
        ]

        return float(
            len(
                self._attack_hist[ip]
            )
        )

    # ========================================================
    # BEHAVIORAL DRIFT
    # ========================================================

    def _drift(self, ip, cnt):

        h = self._pkt_hist[ip]

        h.append(cnt)

        if len(h) > 20:

            h.pop(0)

        if len(h) < 5:

            return 0.0

        avg = sum(
            h[:-1]
        ) / (
            len(h) - 1
        )

        return abs(
            cnt - avg
        )