import time
from security.password_policy import validate_password
from security.rate_limiter import RateLimiter
from security.token_manager import TokenManager

def test_password_policy():
    assert validate_password("weak", "alice")[0] is False
    assert validate_password("Strong-Password-123!", "alice")[0] is True

def test_rate_limiter():
    r = RateLimiter(2, 60)
    assert r.allow("x")[0]
    assert r.allow("x")[0]
    assert r.allow("x")[0] is False

def test_refresh_rotation():
    tm = TokenManager()
    access, refresh = tm.issue("alice", "admin", "sess1")
    assert access and refresh
    rotated = tm.rotate(refresh)
    assert rotated
    assert tm.rotate(refresh) is None
    tm.revoke_session("sess1")
    assert tm.validate_access(access) is None
