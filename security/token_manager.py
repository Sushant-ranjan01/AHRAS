"""Refresh-token rotation and revocation for AHRAS."""
import hashlib, secrets, time
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from config import config

ALGORITHM = "HS256"

class TokenManager:
    def __init__(self):
        self._refresh = {}  # sha256(token) -> {sub, session_id, exp, used}
        self._revoked_sessions = set()

    @staticmethod
    def _hash(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def issue(self, username, role, session_id):
        access = jwt.encode({
            "sub": username, "role": role, "session_id": session_id,
            "type": "access",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES),
        }, config.SECRET_KEY, algorithm=ALGORITHM)
        raw = secrets.token_urlsafe(48)
        self._refresh[self._hash(raw)] = {
            "sub": username, "role": role, "session_id": session_id,
            "exp": time.time() + config.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
            "used": False,
        }
        return access, raw

    def rotate(self, refresh_token):
        key = self._hash(refresh_token)
        record = self._refresh.get(key)
        if not record or record["used"] or record["exp"] <= time.time():
            return None
        record["used"] = True
        if record["session_id"] in self._revoked_sessions:
            return None
        return self.issue(record["sub"], record["role"], record["session_id"])

    def revoke_session(self, session_id):
        if session_id:
            self._revoked_sessions.add(session_id)

    def validate_access(self, token):
        try:
            payload = jwt.decode(token, config.SECRET_KEY, algorithms=[ALGORITHM])
            if payload.get("type", "access") != "access":
                return None
            if payload.get("session_id") in self._revoked_sessions:
                return None
            return payload
        except JWTError:
            return None

    def cleanup(self):
        now = time.time()
        self._refresh = {k:v for k,v in self._refresh.items() if v["exp"] > now and not v["used"]}
