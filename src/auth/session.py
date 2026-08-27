from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from .config import AuthSettings


def configure_session(app: FastAPI, settings: AuthSettings) -> None:
    """Attach Starlette's itsdangerous-signed session cookie middleware.

    Must be called immediately after `FastAPI()` and before
    `app.include_router(...)` or any route that reads `request.session`
    (Starlette applies middleware in reverse-registration order, so
    routers mounted before this won't see a session).

    `same_site` is hardcoded to `"lax"`, not exposed via `AuthSettings`:
    Keycloak's redirect back to `/callback` is a top-level cross-site
    navigation, and `same_site="strict"` would silently drop the cookie —
    login would just leave the session empty, with no error to debug from.

    Args:
        app: The FastAPI app to attach session middleware to.
        settings: Loaded `AuthSettings`. Provides the signing secret and
            cookie name/lifetime/https-only flag.
    """
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.session_secret_key.get_secret_value(),
        session_cookie=settings.session_cookie_name,
        max_age=settings.session_max_age_seconds,
        same_site="lax",
        https_only=settings.session_https_only,
    )