"""
AHRAS v4 — Zero-Trust Continuous Adaptive Risk Engine (ZTRE)
(Phase 2 — Research Contribution, sits next to weight_learner.py)
═══════════════════════════════════════════════════════════════════════════
Problem: session tokens today are typically issued once with a fixed TTL
(e.g. "valid for 8 hours") regardless of what happens during the session.
A user/service whose risk score spikes mid-session (new anomalous behavior,
IOC match, honeypot hit tied to their IP) keeps full access until the
token naturally expires.

Solution: continuous, not point-in-time, trust evaluation. Every time a
session's risk score is recomputed (risk_engine fires again for that
source), ZTRE compares it to the session's last known score and reacts to
the *delta*, not just the absolute value:
  - risk jumps up sharply        -> shrink TTL hard, drop to minimal scope
  - risk is high but stable      -> shrink TTL moderately
  - risk falls / stays low       -> restore normal TTL and scope
  - risk crosses a hard ceiling  -> revoke immediately (scope = NONE)

This is a policy engine, not a token issuer — it doesn't mint or validate
JWTs itself (that's auth/). It tells auth/rbac what TTL and scope a given
session *should* have right now, and it should be called after every
routine risk_engine scoring pass for sessions tied to that source IP/user.
"""
import time
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional

logger = logging.getLogger("ahras.adaptive_learning.ztre")


class AccessScope(str, Enum):
    FULL = "full"                 # normal access
    RESTRICTED = "restricted"     # read-only / no destructive actions
    MINIMAL = "minimal"           # auth-only, no data access
    REVOKED = "revoked"           # session killed, must re-authenticate


# TTL in seconds for each scope tier — deliberately short at the risky end
SCOPE_TTL = {
    AccessScope.FULL: 8 * 3600,
    AccessScope.RESTRICTED: 20 * 60,
    AccessScope.MINIMAL: 5 * 60,
    AccessScope.REVOKED: 0,
}

RISK_CEILING_REVOKE = 90.0        # absolute risk score -> immediate revoke
DELTA_SHARP_RISE = 25.0           # jump in risk score within one eval -> shrink hard
HIGH_RISK_FLOOR = 60.0            # sustained-high threshold


@dataclass
class SessionPolicy:
    session_id: str
    subject: str                  # username or source IP
    scope: AccessScope
    ttl_seconds: int
    last_risk: float
    reason: str
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id, "subject": self.subject,
            "scope": self.scope.value, "ttl_seconds": self.ttl_seconds,
            "last_risk": self.last_risk, "reason": self.reason,
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.updated_at)),
        }


class ZTREEngine:
    def __init__(self):
        self._sessions: Dict[str, SessionPolicy] = {}
        logger.info("ZTREEngine ready")

    def update_session(self, session_id: str, subject: str, risk_score: float) -> SessionPolicy:
        """
        Call this every time risk_engine produces a fresh score for a
        source tied to an active session. Returns the new policy the
        session should immediately be constrained to.
        """
        prev = self._sessions.get(session_id)
        prev_risk = prev.last_risk if prev else 0.0
        delta = risk_score - prev_risk

        scope, reason = self._decide_scope(risk_score, delta)
        ttl = SCOPE_TTL[scope]

        policy = SessionPolicy(
            session_id=session_id, subject=subject, scope=scope,
            ttl_seconds=ttl, last_risk=risk_score, reason=reason,
        )
        self._sessions[session_id] = policy

        if scope in (AccessScope.MINIMAL, AccessScope.REVOKED):
            logger.warning("ZTRE: session %s (%s) downgraded to %s — %s",
                            session_id, subject, scope.value, reason)
        return policy

    @staticmethod
    def _decide_scope(risk_score: float, delta: float):
        if risk_score >= RISK_CEILING_REVOKE:
            return AccessScope.REVOKED, f"risk {risk_score:.0f} at/above revoke ceiling {RISK_CEILING_REVOKE:.0f}"
        if delta >= DELTA_SHARP_RISE:
            return AccessScope.MINIMAL, f"risk jumped +{delta:.0f} in one evaluation window"
        if risk_score >= HIGH_RISK_FLOOR:
            return AccessScope.RESTRICTED, f"sustained high risk ({risk_score:.0f})"
        return AccessScope.FULL, "risk within normal bounds"

    def get_session(self, session_id: str) -> Optional[SessionPolicy]:
        return self._sessions.get(session_id)

    def revoke(self, session_id: str, reason: str = "manual revoke"):
        prev = self._sessions.get(session_id)
        subject = prev.subject if prev else "unknown"
        policy = SessionPolicy(
            session_id=session_id, subject=subject, scope=AccessScope.REVOKED,
            ttl_seconds=0, last_risk=prev.last_risk if prev else 0.0, reason=reason,
        )
        self._sessions[session_id] = policy
        return policy

    def active_sessions(self) -> Dict[str, dict]:
        now = time.time()
        return {
            sid: p.to_dict() for sid, p in self._sessions.items()
            if p.scope != AccessScope.REVOKED and (now - p.updated_at) < p.ttl_seconds
        }


# Singleton, consistent with the rest of the codebase's module-level instances
ztre_engine = ZTREEngine()
