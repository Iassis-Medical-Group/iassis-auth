from typing import Any

from fastapi import HTTPException, Request

from .config import AuthSettings


def make_require_roles(settings: AuthSettings):
    """Build session-based role-checking dependencies.

    Returns a `require_roles(roles)` factory; pass `[]` (or call the
    `get_current_claims` shortcut) to require only an authenticated
    session, with no specific role.

    Reads `request.session["user"]`, populated by `create_auth_router`'s
    `/callback` — requires `SessionMiddleware` to be attached (see
    `configure_session`).

    Note: roles are resolved in `/callback` from the id_token, userinfo,
    and the access token combined (see `keycloak.extract_roles`). The
    stock "roles" client scope puts them in the access token, so a default
    client needs no mapper change. `user["roles"]` only comes back empty
    if that scope isn't assigned to the client at all, or every one of its
    mappers is turned off — in which case `require_roles([...])` denies
    everyone with no obvious error, so check the client config first.

    Args:
        settings: Loaded `AuthSettings`. Accepted for call-shape parity and
            as a future extension point; unused in the current body.
    """

    def require_roles(roles: list[str]):
        def dependency(request: Request) -> Any | None:
            user = request.session.get("user")
            if user is None:
                raise HTTPException(status_code=401, detail="Not authenticated")
            if roles and not any(r in roles for r in user.get("roles", [])):
                raise HTTPException(status_code=403, detail="Authorization failed")
            return user

        return dependency

    def get_current_claims(request: Request) -> Any | None:
        return require_roles([])(request)

    require_roles.get_current_claims = get_current_claims  # type: ignore[attr-defined]
    return require_roles