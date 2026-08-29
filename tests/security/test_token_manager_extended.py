from security.token_manager import TokenManager


def test_access_token_contains_security_claims():
    manager = TokenManager()
    access, refresh = manager.issue("alice", "soc_analyst", "session-1")
    assert refresh
    payload = manager.validate_access(access)
    assert payload is not None
    assert payload["sub"] == "alice"
    assert payload["role"] == "soc_analyst"
    assert payload["session_id"] == "session-1"
    assert payload["type"] == "access"


def test_refresh_rotation_issues_new_refresh_token():
    manager = TokenManager()
    _, refresh = manager.issue("alice", "admin", "session-2")
    rotated = manager.rotate(refresh)
    assert rotated is not None
    new_access, new_refresh = rotated
    assert new_access != ""
    assert new_refresh != refresh
    assert manager.rotate(refresh) is None


def test_revoked_session_invalidates_access_and_refresh():
    manager = TokenManager()
    access, refresh = manager.issue("alice", "admin", "session-3")
    manager.revoke_session("session-3")
    assert manager.validate_access(access) is None
    assert manager.rotate(refresh) is None
