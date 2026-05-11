"""Public API for the iassis-auth library.

Consumers should import from `auth` directly:

    from auth import (
        AuthSettings,
        UserRecord,
        InLogin,
        TokenResponse,
        make_password_hasher,
        make_require_roles,
        create_auth_router,
    )
"""

from .config import AuthSettings
from .dependencies import make_require_roles
from .models import InLogin, TokenResponse, UserRecord
from .router import create_auth_router
from .security import (
    PasswordHasher,
    create_access_token,
    create_refresh_token,
    decode_token,
    make_password_hasher,
)

__all__ = [
    "AuthSettings",
    "InLogin",
    "PasswordHasher",
    "TokenResponse",
    "UserRecord",
    "create_access_token",
    "create_auth_router",
    "create_refresh_token",
    "decode_token",
    "make_password_hasher",
    "make_require_roles",
]