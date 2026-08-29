import pytest

from auth.manager import AccountLockedError, AuthManager
from rbac.permissions import Role


@pytest.mark.security
def test_all_enterprise_roles_can_be_created():
    manager = AuthManager()
    roles = {
        "admin": Role.ADMIN,
        "soc": Role.SOC_ANALYST,
        "hunter": Role.THREAT_HUNTER,
        "responder": Role.INCIDENT_RESPONDER,
        "manager": Role.MANAGER,
    }
    for username, role in roles.items():
        user = manager.create_user(username, "Strong-Test-Password-123!", role)
        assert user.role is role
        assert manager.get_user(username).role is role


@pytest.mark.security
def test_failed_login_lockout_is_enforced():
    manager = AuthManager()
    manager.create_user("locktest", "Strong-Test-Password-123!", Role.SOC_ANALYST)

    for _ in range(manager.MAX_FAILED_ATTEMPTS - 1):
        assert manager.authenticate("locktest", "wrong-password") is None

    with pytest.raises(AccountLockedError):
        manager.authenticate("locktest", "wrong-password")


@pytest.mark.security
def test_inactive_user_cannot_authenticate():
    manager = AuthManager()
    user = manager.create_user("inactive", "Strong-Test-Password-123!", Role.MANAGER)
    user.is_active = False
    assert manager.authenticate("inactive", "Strong-Test-Password-123!") is None
