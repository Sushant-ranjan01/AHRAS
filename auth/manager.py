"""
AHRAS — Authentication & Authorization Manager

Roles:
    Unified with rbac.permissions.Role.

Five enterprise roles:
    ADMIN
    SOC_ANALYST
    THREAT_HUNTER
    INCIDENT_RESPONDER
    MANAGER

Legacy MASTER/ANALYST aliases are kept for backward compatibility.

Authentication features:
    - bcrypt password hashing
    - strong password policy
    - JWT access tokens
    - refresh-token rotation
    - session tracking
    - logout/revocation
    - brute-force protection
    - account lockout
    - RBAC integration
"""

import time
import threading
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
    """Raised when an account is temporarily locked."""

    def __init__(self, retry_after_secs: int):
        self.retry_after_secs = retry_after_secs
        super().__init__(
            f"Account locked — retry in {retry_after_secs}s"
        )


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------

import bcrypt as _bcrypt_lib


class _PwdContext:
    """
    Drop-in replacement for passlib's CryptContext.

    passlib 1.7.4 is incompatible with newer bcrypt versions because
    bcrypt removed the __about__ module.

    This shim uses bcrypt directly.
    """

    def hash(self, secret: str) -> str:
        return _bcrypt_lib.hashpw(
            secret.encode("utf-8"),
            _bcrypt_lib.gensalt()
        ).decode("utf-8")

    def verify(self, secret: str, hashed: str) -> bool:
        try:
            return _bcrypt_lib.checkpw(
                secret.encode("utf-8"),
                hashed.encode("utf-8")
            )
        except Exception:
            return False


if _USE_PASSLIB:
    try:
        _test_ctx = CryptContext(
            schemes=["bcrypt"],
            deprecated="auto"
        )

        # Test whether the installed passlib/bcrypt combination works.
        _test_ctx.hash("test")

        pwd_context = _test_ctx

    except Exception:
        pwd_context = _PwdContext()
else:
    pwd_context = _PwdContext()


# ---------------------------------------------------------------------------
# Authentication dependencies
# ---------------------------------------------------------------------------

from auth.dependencies import (
    oauth2_scheme,
    get_current_user,
)

from security.password_policy import validate_password
from security.token_manager import TokenManager


ALGORITHM = "HS256"


# ---------------------------------------------------------------------------
# User model
# ---------------------------------------------------------------------------

@dataclass
class User:
    username: str
    hashed_password: str
    role: UserRole

    full_name: str = ""
    email: str = ""

    is_active: bool = True

    created_at: float = field(
        default_factory=time.time
    )

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


# ---------------------------------------------------------------------------
# Login history
# ---------------------------------------------------------------------------

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
            seconds = int(
                self.logout_time - self.login_time
            )
        else:
            seconds = int(
                time.time() - self.login_time
            )

        return (
            f"{seconds // 3600:02d}:"
            f"{(seconds % 3600) // 60:02d}:"
            f"{seconds % 60:02d}"
        )

    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "role": self.role,
            "login_time": datetime.fromtimestamp(
                self.login_time
            ).strftime("%Y-%m-%d %H:%M:%S"),

            "ip_address": self.ip_address,
            "success": self.success,
            "session_id": self.session_id,

            "logout_time": (
                datetime.fromtimestamp(
                    self.logout_time
                ).strftime("%Y-%m-%d %H:%M:%S")
                if self.logout_time
                else None
            ),

            "duration": self.duration_str,

            "active": (
                self.logout_time is None
                and self.success
            ),
        }


# ---------------------------------------------------------------------------
# Authentication manager
# ---------------------------------------------------------------------------

class AuthManager:
    """Thread-safe user and session manager."""

    # -----------------------------------------------------------------------
    # Brute-force protection
    # -----------------------------------------------------------------------

    MAX_FAILED_ATTEMPTS = 5

    LOCKOUT_WINDOW_SECS = 5 * 60

    LOCKOUT_DURATION_SECS = 15 * 60

    # -----------------------------------------------------------------------
    # Initialization
    # -----------------------------------------------------------------------

    def __init__(self):
        self._users: Dict[str, User] = {}

        self._login_history: List[LoginRecord] = []

        self._active_sessions: Dict[
            str,
            LoginRecord
        ] = {}

        self._failed_attempts: Dict[
            str,
            List[float]
        ] = {}

        self._locked_until: Dict[
            str,
            float
        ] = {}

        self._lock = threading.Lock()

        self.tokens = TokenManager()

        self._seed_default_users()

    # -----------------------------------------------------------------------
    # Default users
    # -----------------------------------------------------------------------

    def _seed_default_users(self):
        """
        Create one default account per RBAC role.

        These accounts are intended for development/testing only.

        Each seeded account is marked with must_change_password=True.

        IMPORTANT:
        The passwords below intentionally do NOT contain the username,
        because the password policy rejects passwords containing the
        username.
        """

        for username, pw, role, name, email in [

            (
                "admin",
                "Zx7!Qm29#Lp4",
                UserRole.ADMIN,
                "System Administrator",
                "admin@ahras.local",
            ),

            (
                "analyst",
                "Vt8@Kp41!Rs6",
                UserRole.SOC_ANALYST,
                "SOC Analyst",
                "analyst@ahras.local",
            ),

            (
                "manager",
                "Nq5#Wx83@Tb7",
                UserRole.MANAGER,
                "Security Manager",
                "manager@ahras.local",
            ),

            (
                "hunter",
                "Jr9!Md52#Qx8",
                UserRole.THREAT_HUNTER,
                "Threat Hunter",
                "hunter@ahras.local",
            ),

            (
                "responder",
                "Lp4@Zk76!Nv2",
                UserRole.INCIDENT_RESPONDER,
                "Incident Responder",
                "responder@ahras.local",
            ),

        ]:

            self.create_user(
                username,
                pw,
                role,
                name,
                email,
            )

            self._users[
                username
            ].must_change_password = True

    # -----------------------------------------------------------------------
    # User CRUD
    # -----------------------------------------------------------------------

    def create_user(
        self,
        username: str,
        password: str,
        role: UserRole,
        full_name: str = "",
        email: str = "",
    ) -> User:

        ok, reason = validate_password(
            password,
            username
        )

        if not ok:
            raise ValueError(reason)

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

    # -----------------------------------------------------------------------
    # Get user
    # -----------------------------------------------------------------------

    def get_user(
        self,
        username: str
    ) -> Optional[User]:

        with self._lock:
            return self._users.get(username)

    # -----------------------------------------------------------------------
    # List users
    # -----------------------------------------------------------------------

    def list_users(self) -> List[dict]:

        with self._lock:
            return [
                user.to_dict()
                for user in self._users.values()
            ]

    # -----------------------------------------------------------------------
    # Password verification
    # -----------------------------------------------------------------------

    def verify_password(
        self,
        plain: str,
        hashed: str
    ) -> bool:

        return pwd_context.verify(
            plain,
            hashed
        )

    # -----------------------------------------------------------------------
    # Lockout
    # -----------------------------------------------------------------------

    def _is_locked(
        self,
        username: str
    ) -> Optional[float]:

        until = self._locked_until.get(
            username
        )

        if until and time.time() < until:
            return until - time.time()

        if until:
            del self._locked_until[
                username
            ]

        return None

    def _record_failed_attempt(
        self,
        username: str
    ):

        now = time.time()

        attempts = [
            timestamp
            for timestamp
            in self._failed_attempts.get(
                username,
                []
            )
            if now - timestamp
            < self.LOCKOUT_WINDOW_SECS
        ]

        attempts.append(now)

        self._failed_attempts[
            username
        ] = attempts

        if len(attempts) >= self.MAX_FAILED_ATTEMPTS:

            self._locked_until[
                username
            ] = (
                now
                + self.LOCKOUT_DURATION_SECS
            )

            logger_ahras_auth.warning(
                f"Account '{username}' locked for "
                f"{self.LOCKOUT_DURATION_SECS}s after "
                f"{len(attempts)} failed login attempts "
                f"within {self.LOCKOUT_WINDOW_SECS}s"
            )

    # -----------------------------------------------------------------------
    # Authentication
    # -----------------------------------------------------------------------

    def authenticate(
        self,
        username: str,
        password: str,
        ip: str = "unknown",
    ) -> Optional[str]:

        """
        Authenticate user and return JWT access token.

        Raises:
            AccountLockedError
                If account is temporarily locked.
        """

        with self._lock:
            remaining = self._is_locked(
                username
            )

        if remaining is not None:
            raise AccountLockedError(
                int(remaining) + 1
            )

        user = self.get_user(
            username
        )

        success = (
            user is not None
            and user.is_active
            and self.verify_password(
                password,
                user.hashed_password
            )
        )

        session_id = (
            secrets.token_hex(16)
            if success
            else ""
        )

        record = LoginRecord(
            username=username,
            role=(
                user.role.value
                if user
                else "unknown"
            ),
            login_time=time.time(),
            ip_address=ip,
            success=success,
            session_id=session_id,
        )

        with self._lock:

            self._login_history.insert(
                0,
                record
            )

            if len(
                self._login_history
            ) > 1000:

                self._login_history.pop()

            if success:

                self._active_sessions[
                    session_id
                ] = record

                self._failed_attempts.pop(
                    username,
                    None
                )

            else:

                self._record_failed_attempt(
                    username
                )

        if not success:
            return None

        token_data = {
            "sub": username,
            "role": user.role.value,
            "session_id": session_id,
            "exp": (
                datetime.now(timezone.utc)
                + timedelta(
                    minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES
                )
            ),
        }

        return jwt.encode(
            token_data,
            config.SECRET_KEY,
            algorithm=ALGORITHM,
        )

    # -----------------------------------------------------------------------
    # Refresh token
    # -----------------------------------------------------------------------

    def issue_refresh_for(
        self,
        username: str
    ) -> Optional[str]:

        user = self.get_user(
            username
        )

        if not user:
            return None

        with self._lock:

            sessions = [
                record
                for record
                in self._active_sessions.values()
                if record.username == username
            ]

            if not sessions:
                return None

            session_id = sessions[
                -1
            ].session_id

        return self.tokens.issue(
            username,
            user.role.value,
            session_id,
        )[1]

    # -----------------------------------------------------------------------
    # Change password
    # -----------------------------------------------------------------------

    def change_password(
        self,
        username: str,
        old_password: str,
        new_password: str,
    ) -> bool:

        """
        Verify old password and set a new password.

        Returns:
            True  -> password changed
            False -> verification/policy failure
        """

        user = self.get_user(
            username
        )

        if (
            not user
            or not self.verify_password(
                old_password,
                user.hashed_password,
            )
        ):
            return False

        ok, _reason = validate_password(
            new_password,
            username
        )

        if not ok:
            return False

        with self._lock:

            user.hashed_password = (
                pwd_context.hash(
                    new_password
                )
            )

            user.must_change_password = False

        logger_ahras_auth.info(
            f"Password changed for user '{username}'"
        )

        return True

    # -----------------------------------------------------------------------
    # Token decoding
    # -----------------------------------------------------------------------

    def decode_token(
        self,
        token: str
    ) -> Optional[dict]:

        return self.tokens.validate_access(
            token
        )

    # -----------------------------------------------------------------------
    # Token refresh
    # -----------------------------------------------------------------------

    def refresh(
        self,
        refresh_token: str
    ):

        return self.tokens.rotate(
            refresh_token
        )

    # -----------------------------------------------------------------------
    # Logout
    # -----------------------------------------------------------------------

    def logout(
        self,
        session_id: str
    ):

        self.tokens.revoke_session(
            session_id
        )

        with self._lock:

            if session_id in self._active_sessions:

                self._active_sessions[
                    session_id
                ].logout_time = time.time()

                del self._active_sessions[
                    session_id
                ]

    # -----------------------------------------------------------------------
    # Login history
    # -----------------------------------------------------------------------

    def login_history(
        self,
        limit: int = 50
    ) -> List[dict]:

        with self._lock:

            return [
                record.to_dict()
                for record
                in self._login_history[:limit]
            ]

    # -----------------------------------------------------------------------
    # Active sessions
    # -----------------------------------------------------------------------

    def active_sessions(
        self
    ) -> List[dict]:

        with self._lock:

            return [
                record.to_dict()
                for record
                in self._active_sessions.values()
            ]


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------

_auth_manager_instance: Optional[
    AuthManager
] = None


def get_auth_manager() -> AuthManager:

    global _auth_manager_instance

    if _auth_manager_instance is None:
        _auth_manager_instance = AuthManager()

    return _auth_manager_instance


# ---------------------------------------------------------------------------
# Superuser roles
# ---------------------------------------------------------------------------

_SUPERUSER_ROLES = {
    UserRole.ADMIN.value,
    UserRole.MASTER.value,
}


# ---------------------------------------------------------------------------
# Admin dependency
# ---------------------------------------------------------------------------

async def require_master(
    current_user: dict = Depends(
        get_current_user
    )
) -> dict:

    """
    Backward-compatible dependency used by existing routes.

    Only ADMIN / legacy MASTER users can access
    administrator-level routes.
    """

    if (
        current_user.get("role")
        not in _SUPERUSER_ROLES
    ):

        raise HTTPException(
            status_code=403,
            detail="Admin role required",
        )

    return current_user