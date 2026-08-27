"""Public API for the iassis-auth library.

Consumers should import from `auth` directly:

    from auth import (
        AuthSettings,
        configure_session,
        create_auth_router,
        make_require_roles,
    )
"""

from .config import AuthSettings
from .dependencies import make_require_roles
from .models import ErrorResponse
from .router import create_auth_router
from .session import configure_session

__all__ = [
    "AuthSettings",
    "ErrorResponse",
    "configure_session",
    "create_auth_router",
    "make_require_roles",
]