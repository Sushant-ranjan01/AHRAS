"""
AHRAS — Authentication & Authorization Manager
Roles: unified with rbac.permissions.Role (five enterprise roles: ADMIN,
SOC_ANALYST, THREAT_HUNTER, INCIDENT_RESPONDER, MANAGER, plus the legacy
MASTER/ANALYST aliases kept for backward compatibility). Previously this
module defined its own two-role UserRole(MASTER/ANALYST) enum that had no
relationship to rbac/permissions.py's five-role Role enum -- the JWT could
only ever carry "master" or "analyst", so THREAT_HUNTER/INCIDENT_RESPONDER/
SOC_ANALYST/MANAGER, though fully defined with their own permission sets in
rbac/permissions.py, could never actually be assigned to a user or land in
a token. rbac.permissions.Role is now the single source of truth for what
a "role" is; UserRole is kept as a name for backward-compatible imports.
"""

import time
import threading
import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from jose import JWTError, jwt
from rbac.permissions import Role as UserRole
try:
    from passlib.context import CryptContext
    _USE_PASSLIB = True
except Exception:
    _USE_PASSLIB = False
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from config import config

logger_ahras_auth = logging.getLogger("ahras.auth")


class AccountLockedError(Exception):
    """Raised by AuthManager.authenticate() when an account is temporarily
    locked out after too many failed login attempts."""
    def __init__(self, retry_after_secs: int):
        self.retry_after_secs = retry_after_secs
        super().__init__(f"Account locked — retry in {retry_after_secs}s")

import bcrypt as _bcrypt_lib

class _PwdContext:
    """
    Drop-in shim for passlib's CryptContext.
    passlib 1.7.4 is incompatible with bcrypt 5.x (removed __about__ module).
    This shim calls bcrypt directly so no passlib involvement at hash time.
    """
    def hash(self, secret: str) -> str:
        return _bcrypt_lib.hashpw(
            secret.encode("utf-8"), _bcrypt_lib.gensalt()
        ).decode("utf-8")

    def verify(self, secret: str, hashed: str) -> bool:
        try:
            return _bcrypt_lib.checkpw(
                secret.encode("utf-8"), hashed.encode("utf-8")
            )
        except Exception:
            return False

if _USE_PASSLIB:
    try:
        _test_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
        _test_ctx.hash("test")          # will raise if passlib+bcrypt broken
        pwd_context = _test_ctx
    except Exception:
        pwd_context = _PwdContext()
else:
    pwd_context = _PwdContext()
from auth.dependencies import oauth2_scheme, get_current_user  # noqa: F401 (re-exported)

ALGORITHM = "HS256"


@dataclass
class User:
    username: str
    hashed_password: str
    role: UserRole
    full_name: str = ""
    email: str = ""
    is_active: bool = True
    created_at: float = field(default_factory=time.time)
    must_change_password: bool = False

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "role": self.role.value,
            "full_name": self.full_name,
            "email": self.email,
            "is_active": self.is_active,
            "created_at": self.created_at,
            "must_change_password": self.must_change_password,
        }


@dataclass
class LoginRecord:
    username: str
    role: str
    login_time: float
    ip_address: str
    success: bool
    session_id: str = ""
    logout_time: Optional[float] = None

    @property
    def duration_str(self) -> str:
        if self.logout_time:
            s = int(self.logout_time - self.login_time)
        else:
            s = int(time.time() - self.login_time)
        return f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "role": self.role,
            "login_time": datetime.fromtimestamp(self.login_time).strftime("%Y-%m-%d %H:%M:%S"),
            "ip_address": self.ip_address,
            "success": self.success,
            "session_id": self.session_id,
            "logout_time": datetime.fromtimestamp(self.logout_time).strftime("%Y-%m-%d %H:%M:%S") if self.logout_time else None,
            "duration": self.duration_str,
            "active": self.logout_time is None and self.success,
        }


class AuthManager:
    """Thread-safe user and session manager."""

    # Brute-force lockout: after MAX_FAILED_ATTEMPTS failed logins for a
    # username within LOCKOUT_WINDOW_SECS, that username is locked out for
    # LOCKOUT_DURATION_SECS regardless of whether the next attempt has the
    # correct password. Keyed on username (not IP) since AHRAS sits behind
    # NAT/VPN in most SOC deployments where many analysts share one egress IP.
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_WINDOW_SECS = 5 * 60
    LOCKOUT_DURATION_SECS = 15 * 60

    def __init__(self):
        self._users: Dict[str, User] = {}
        self._login_history: List[LoginRecord] = []
        self._active_sessions: Dict[str, LoginRecord] = {}
        self._failed_attempts: Dict[str, List[float]] = {}
        self._locked_until: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._seed_default_users()

    def _seed_default_users(self):
        """Create one default account per RBAC role. Flagged so the
        dashboard can prompt for a password change on first login — these
        credentials are public (they're in the README) and must not be left
        in place for a real deployment.

        BUG FIX: 'manager' used to be seeded with UserRole.MASTER (full
        admin), not UserRole.MANAGER — a symptom of the old two-role
        auth/RBAC mismatch where MANAGER (a real, more restricted role
        defined in rbac/permissions.py) could never actually be assigned.
        It now gets its own role, and two more accounts are seeded so all
        five RBAC roles are actually reachable/testable out of the box."""
        for username, pw, role, name, email in [
            ("admin",    "Admin@123",    UserRole.ADMIN,              "System Administrator", "admin@ahras.local"),
            ("analyst",  "Analyst@123",  UserRole.SOC_ANALYST,        "SOC Analyst",           "analyst@ahras.local"),
            ("manager",  "Manager@123",  UserRole.MANAGER,            "Security Manager",      "manager@ahras.local"),
            ("hunter",   "Hunter@123",   UserRole.THREAT_HUNTER,      "Threat Hunter",         "hunter@ahras.local"),
            ("responder","Responder@123", UserRole.INCIDENT_RESPONDER, "Incident Responder",   "responder@ahras.local"),
        ]:
            self.create_user(username, pw, role, name, email)
            self._users[username].must_change_password = True

    # ── User CRUD ──────────────────────────────────────────────────────────────

    def create_user(self, username: str, password: str, role: UserRole,
                    full_name: str = "", email: str = "") -> User:
        user = User(
            username=username,
            hashed_password=pwd_context.hash(password),
            role=role,
            full_name=full_name,
            email=email,
        )
        with self._lock:
            self._users[username] = user
        return user

    def get_user(self, username: str) -> Optional[User]:
        with self._lock:
            return self._users.get(username)

    def list_users(self) -> List[dict]:
        with self._lock:
            return [u.to_dict() for u in self._users.values()]

    def verify_password(self, plain: str, hashed: str) -> bool:
        return pwd_context.verify(plain, hashed)

    # ── Auth flow ─────────────────────────────────────────────────────────────

    def _is_locked(self, username: str) -> Optional[float]:
        """Returns seconds remaining if locked, else None."""
        until = self._locked_until.get(username)
        if until and time.time() < until:
            return until - time.time()
        if until:
            del self._locked_until[username]
        return None

    def _record_failed_attempt(self, username: str):
        now = time.time()
        attempts = [t for t in self._failed_attempts.get(username, []) if now - t < self.LOCKOUT_WINDOW_SECS]
        attempts.append(now)
        self._failed_attempts[username] = attempts
        if len(attempts) >= self.MAX_FAILED_ATTEMPTS:
            self._locked_until[username] = now + self.LOCKOUT_DURATION_SECS
            logger_ahras_auth.warning(
                f"Account '{username}' locked for {self.LOCKOUT_DURATION_SECS}s after "
                f"{len(attempts)} failed login attempts within {self.LOCKOUT_WINDOW_SECS}s"
            )

    def authenticate(self, username: str, password: str, ip: str = "unknown") -> Optional[str]:
        """Authenticate user and return JWT token. Records login attempt.
        Raises AccountLockedError if the account is currently locked out from
        repeated failed attempts — caller (main.py) should surface this as a
        429, not a generic 401, so the user knows to wait rather than retry."""
        with self._lock:
            remaining = self._is_locked(username)
        if remaining is not None:
            raise AccountLockedError(int(remaining) + 1)

        user = self.get_user(username)
        success = user is not None and user.is_active and self.verify_password(password, user.hashed_password)

        session_id = secrets.token_hex(16) if success else ""
        record = LoginRecord(
            username=username,
            role=user.role.value if user else "unknown",
            login_time=time.time(),
            ip_address=ip,
            success=success,
            session_id=session_id,
        )

        with self._lock:
            self._login_history.insert(0, record)
            if len(self._login_history) > 1000:
                self._login_history.pop()
            if success:
                self._active_sessions[session_id] = record
                self._failed_attempts.pop(username, None)
            else:
                self._record_failed_attempt(username)

        if not success:
            return None

        token_data = {
            "sub": username,
            "role": user.role.value,
            "session_id": session_id,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES),
        }
        return jwt.encode(token_data, config.SECRET_KEY, algorithm=ALGORITHM)

    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Verifies old_password, then sets new_password and clears the
        must_change_password flag. Returns False if old_password is wrong."""
        user = self.get_user(username)
        if not user or not self.verify_password(old_password, user.hashed_password):
            return False
        with self._lock:
            user.hashed_password = pwd_context.hash(new_password)
            user.must_change_password = False
        logger_ahras_auth.info(f"Password changed for user '{username}'")
        return True

    def decode_token(self, token: str) -> Optional[dict]:
        try:
            return jwt.decode(token, config.SECRET_KEY, algorithms=[ALGORITHM])
        except JWTError:
            return None

    def logout(self, session_id: str):
        with self._lock:
            if session_id in self._active_sessions:
                self._active_sessions[session_id].logout_time = time.time()
                del self._active_sessions[session_id]

    # ── Login history ─────────────────────────────────────────────────────────

    def login_history(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return [r.to_dict() for r in self._login_history[:limit]]

    def active_sessions(self) -> List[dict]:
        with self._lock:
            return [r.to_dict() for r in self._active_sessions.values()]


# ── FastAPI dependency ────────────────────────────────────────────────────────

_auth_manager_instance: Optional[AuthManager] = None

def get_auth_manager() -> AuthManager:
    global _auth_manager_instance
    if _auth_manager_instance is None:
        _auth_manager_instance = AuthManager()
    return _auth_manager_instance


# get_current_user is now defined in auth.dependencies (imported/re-exported
# above) -- see that module's docstring for why. Kept out of this module
# body to avoid reintroducing the circular import this file used to have.

_SUPERUSER_ROLES = {UserRole.ADMIN.value, UserRole.MASTER.value}


async def require_master(current_user: dict = Depends(get_current_user)) -> dict:
    """Kept as the name every existing route in main.py already depends on
    (Depends(require_master)). Now checks against the unified Role enum's
    ADMIN (and the legacy MASTER alias, which maps to the same permission
    set) instead of a role value that could never be anything but "master"."""
    if current_user.get("role") not in _SUPERUSER_ROLES:
        raise HTTPException(status_code=403, detail="Admin role required")
    return current_user
