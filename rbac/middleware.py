"""
AHRAS v6 — RBAC FastAPI Dependencies
=====================================
Drop-in replacements / extensions for the original require_master().

Usage in routes:
    from rbac import require_permission, require_role
    from rbac.permissions import Perm, Role

    @app.get("/api/hunt/ip/{ip}")
    async def hunt_ip(ip: str, _=Depends(require_permission(Perm.HUNT_EXECUTE))):
        ...

    @app.post("/api/firewall/toggle")
    async def toggle_fw(req, _=Depends(require_role(Role.ADMIN))):
        ...
"""

import logging
from functools import lru_cache
from typing import Set

from fastapi import Depends, HTTPException, status

from .permissions import Perm, Role, get_permissions, has_permission

logger = logging.getLogger("ahras.rbac")

# Import the existing auth dependency (avoid circular import via string)
def _get_auth_dep():
    from auth.dependencies import get_current_user
    return get_current_user


# ── Core dependency factories ─────────────────────────────────────────────────

def require_permission(perm: Perm):
    """
    FastAPI dependency factory.
    Returns a dependency that enforces a single permission.

    Example:
        @app.get("/api/hunt/ip/{ip}")
        async def hunt_ip(ip, _=Depends(require_permission(Perm.HUNT_EXECUTE))):
    """
    async def _check(current_user: dict = Depends(_get_auth_dep())):
        role = current_user.get("role", "")
        if not has_permission(role, perm):
            logger.warning(
                f"RBAC DENY: user={current_user.get('sub','?')} "
                f"role={role} perm={perm.value}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{perm.value}' required for this action. "
                       f"Your role '{role}' does not have this permission.",
            )
        return current_user
    return _check


def require_any_permission(*perms: Perm):
    """
    Dependency that passes if the user has ANY of the listed permissions.
    Useful for endpoints that serve multiple roles differently.
    """
    async def _check(current_user: dict = Depends(_get_auth_dep())):
        role = current_user.get("role", "")
        user_perms = get_permissions(role)
        if not any(p in user_perms for p in perms):
            perm_list = ", ".join(p.value for p in perms)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"One of [{perm_list}] is required. Your role: {role}",
            )
        return current_user
    return _check


def require_all_permissions(*perms: Perm):
    """
    Dependency that passes only if the user has ALL listed permissions.
    """
    async def _check(current_user: dict = Depends(_get_auth_dep())):
        role = current_user.get("role", "")
        user_perms = get_permissions(role)
        missing = [p.value for p in perms if p not in user_perms]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permissions: {', '.join(missing)}",
            )
        return current_user
    return _check


def require_role(*roles: Role):
    """
    Dependency that enforces role membership (no permission lookup).
    Useful for admin-only operations.
    """
    role_values = {r.value for r in roles}

    async def _check(current_user: dict = Depends(_get_auth_dep())):
        user_role = current_user.get("role", "")
        if user_role not in role_values:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role must be one of: {', '.join(role_values)}. "
                       f"Your role: {user_role}",
            )
        return current_user
    return _check


# ── Convenience singletons (pre-built dependencies) ──────────────────────────
# These can be used directly: Depends(require_admin)

require_admin              = require_role(Role.ADMIN, Role.MASTER)
require_soc_analyst        = require_any_permission(Perm.ALERTS_READ)
require_threat_hunter_role = require_any_permission(Perm.HUNT_EXECUTE)
require_incident_responder = require_any_permission(Perm.SOAR_EXECUTE)
require_manager_role       = require_role(Role.MANAGER, Role.ADMIN, Role.MASTER)

# Read-only check — any authenticated user with dashboard permission
require_dashboard          = require_permission(Perm.DASHBOARD_READ)


# ── Helper: get current user's permissions ───────────────────────────────────

async def get_user_permissions(current_user: dict = Depends(_get_auth_dep())) -> dict:
    """
    Dependency that injects the user dict enriched with their permission set.
    Useful in endpoints that behave differently per role (e.g. hide fields).
    """
    role = current_user.get("role", "")
    perms = get_permissions(role)
    return {
        **current_user,
        "permissions": sorted(p.value for p in perms),
        "permission_set": perms,  # Set[Perm] for fast `in` checks
    }
