"""Role-based access control: defines roles, permissions, and route guards."""
from .permissions import Perm, Role, get_permissions, has_permission, role_summary
from .middleware import (
    require_permission, require_any_permission, require_all_permissions,
    require_role, require_admin, require_dashboard, get_user_permissions,
)

__all__ = [
    "Perm", "Role", "get_permissions", "has_permission", "role_summary",
    "require_permission", "require_any_permission", "require_all_permissions",
    "require_role", "require_admin", "require_dashboard", "get_user_permissions",
]
