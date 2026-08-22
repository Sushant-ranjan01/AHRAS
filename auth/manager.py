"""
AHRAS — Authentication & Authorization Manager
Roles:
  MASTER  → full control: block/unblock IPs, manage firewall, see all logs, manage users
  ANALYST → view events, analyze logs, submit reports/alerts to master
"""

import time
import threading
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum

from jose import JWTError, jwt
try:
    from passlib.context import CryptContext
    _USE_PASSLIB = True
except Exception:
    _USE_PASSLIB = False
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from config import config

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
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

ALGORITHM = "HS256"


class UserRole(str, Enum):
    MASTER = "master"
    ANALYST = "analyst"


@dataclass
class User:
    username: str
    hashed_password: str
    role: UserRole
    full_name: str = ""
    email: str = ""
    is_active: bool = True
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "role": self.role.value,
            "full_name": self.full_name,
            "email": self.email,
            "is_active": self.is_active,
            "created_at": self.created_at,
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

    def __init__(self):
        self._users: Dict[str, User] = {}
        self._login_history: List[LoginRecord] = []
        self._active_sessions: Dict[str, LoginRecord] = {}
        self._lock = threading.Lock()
        self._seed_default_users()

    def _seed_default_users(self):
        """Create default MASTER and ANALYST accounts."""
        self.create_user("admin",   "Admin@123",   UserRole.MASTER,  "System Administrator", "admin@ahras.local")
        self.create_user("analyst", "Analyst@123", UserRole.ANALYST, "SOC Analyst",          "analyst@ahras.local")
        self.create_user("manager", "Manager@123", UserRole.MASTER,  "Security Manager",     "manager@ahras.local")

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

    def authenticate(self, username: str, password: str, ip: str = "unknown") -> Optional[str]:
        """Authenticate user and return JWT token. Records login attempt."""
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

        if not success:
            return None

        token_data = {
            "sub": username,
            "role": user.role.value,
            "session_id": session_id,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES),
        }
        return jwt.encode(token_data, config.SECRET_KEY, algorithm=ALGORITHM)

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


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    mgr = get_auth_manager()
    payload = mgr.decode_token(token)
    if payload is None:
        raise credentials_exception
    return payload


async def require_master(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") != UserRole.MASTER.value:
        raise HTTPException(status_code=403, detail="Master role required")
    return current_user
