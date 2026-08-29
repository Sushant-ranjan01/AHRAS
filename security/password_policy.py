"""Password policy for AHRAS authentication."""
import re

COMMON = {"password", "password123", "admin123", "qwerty", "12345678", "changeme"}


def validate_password(password: str, username: str = "") -> tuple[bool, str]:
    if not isinstance(password, str) or len(password) < 12:
        return False, "Password must be at least 12 characters long"
    if len(password) > 128:
        return False, "Password must not exceed 128 characters"
    if password.lower() in COMMON:
        return False, "Password is too common"
    if username and username.lower() in password.lower():
        return False, "Password must not contain the username"
    checks = [r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"]
    if not all(re.search(p, password) for p in checks):
        return False, "Password must contain upper, lower, number, and special character"
    return True, "OK"
