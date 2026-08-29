import pytest

from rbac.permissions import Perm, Role, get_permissions, has_permission


@pytest.mark.security
def test_admin_has_every_permission():
    assert get_permissions(Role.ADMIN.value) == set(Perm)


@pytest.mark.security
def test_read_only_manager_cannot_execute_dangerous_actions():
    assert has_permission(Role.MANAGER.value, Perm.DASHBOARD_READ)
    assert not has_permission(Role.MANAGER.value, Perm.SYSTEM_ADMIN)
    assert not has_permission(Role.MANAGER.value, Perm.FIREWALL_BLOCK)
    assert not has_permission(Role.MANAGER.value, Perm.SOAR_EXECUTE)
    assert not has_permission(Role.MANAGER.value, Perm.IOC_DELETE)


@pytest.mark.security
def test_incident_responder_has_response_but_not_system_admin():
    assert has_permission(Role.INCIDENT_RESPONDER.value, Perm.SOAR_EXECUTE)
    assert has_permission(Role.INCIDENT_RESPONDER.value, Perm.FORENSICS_WRITE)
    assert not has_permission(Role.INCIDENT_RESPONDER.value, Perm.SYSTEM_ADMIN)
    assert not has_permission(Role.INCIDENT_RESPONDER.value, Perm.FIREWALL_TOGGLE)


@pytest.mark.security
def test_unknown_role_has_no_permissions():
    assert get_permissions("does-not-exist") == set()
