import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import AuthSettings
from .security import decode_token

_bearer = HTTPBearer(auto_error=False)


def make_require_roles(settings: AuthSettings):
    """Build role-checking dependencies bound to a specific AuthSettings instance.

    Returns a `require_roles(roles)` factory; pass `[]` (or call the
    `get_current_claims` shortcut) to require only a valid access token.
    """

    def require_roles(roles: list[str]):
        def dependency(
            credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
        ) -> dict:
            if credentials is None:
                raise HTTPException(status_code=401, detail="Not authenticated")
            try:
                payload = decode_token(settings, credentials.credentials)
            except jwt.ExpiredSignatureError:
                raise HTTPException(status_code=401, detail="Token has expired")
            except jwt.InvalidTokenError:
                raise HTTPException(status_code=401, detail="Invalid token")

            if payload.get("type") != "access":
                raise HTTPException(status_code=401, detail="Invalid token type")

            if roles:
                token_roles = payload.get("roles", [])
                if not any(r in roles for r in token_roles):
                    raise HTTPException(status_code=403, detail="Authorization failed")

            return payload

        return dependency

    def get_current_claims(
        credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
    ) -> dict:
        return require_roles([])(credentials)

    require_roles.get_current_claims = get_current_claims  # type: ignore[attr-defined]
    return require_roles