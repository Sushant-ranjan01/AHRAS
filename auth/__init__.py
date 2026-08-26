"""Handles login, JWT tokens, and user/role identity."""
from .manager import AuthManager, User, UserRole, get_current_user
__all__ = ["AuthManager", "User", "UserRole", "get_current_user"]
