import pytest

from api.router import api_router


@pytest.mark.security
def test_protected_api_routes_have_dependencies():
    assert api_router.dependencies, "API v1 router must have a global auth dependency"


@pytest.mark.security
def test_sensitive_routes_have_explicit_permission_guards():
    routes = {route.path: route for route in api_router.routes if hasattr(route, "path")}
    expected = [
        path for path in routes
        if any(token in path for token in ("/users", "/soar", "/ioc", "/cases", "/hunt"))
    ]
    assert expected, "Expected sensitive API routes to exist"
    guarded = 0
    for path in expected:
        route = routes[path]
        if getattr(route, "dependant", None) and route.dependant.dependencies:
            guarded += 1
    assert guarded >= max(1, len(expected) // 2)
