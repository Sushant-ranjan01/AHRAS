"""AHRAS — low-level auth dependency, deliberately kept free of any
import-time dependency on `rbac`.

Fixes a circular import (27-08-26):
  main.py -> auth.manager -> rbac.permissions -> rbac/__init__.py
  -> rbac.middleware -> (at rbac.middleware's own MODULE level, building
  the `require_admin`/`require_manager_role` convenience singletons)
  -> `from auth.manager import get_current_user`

That last import ran while `auth.manager` was still mid-import (we got
here via auth.manager's own top-of-file `from rbac.permissions import
Role`), so Python raised "cannot import name 'get_current_user' from
partially initialized module auth.manager". This made `python main.py`
crash immediately on startup, before the server ever came up.

get_current_user()/oauth2_scheme don't actually need anything from rbac
-- they only need AuthManager, imported lazily inside the function body
so this module carries no import-time dependency on `auth.manager`
either. auth/manager.py re-exports both names below for every existing
caller (main.py, api/router.py, auth/__init__.py) that does
`from auth.manager import get_current_user`.
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    from auth.manager import get_auth_manager  # deferred: avoid import-time cycle

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    mgr = get_auth_manager()
    payload = mgr.decode_token(token)
    if payload is None:
        raise credentials_exception
    return payload
