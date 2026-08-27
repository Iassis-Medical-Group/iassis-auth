from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthSettings(BaseSettings):
    """Configuration for Keycloak login/logout and the session cookie.

    All fields are env-driven with prefix `AUTH_` (e.g.
    `AUTH_KEYCLOAK_URL`, `AUTH_SESSION_SECRET_KEY`). Load once per process
    and pass the same instance to `configure_session`, `create_auth_router`,
    and `make_require_roles`.
    """

    # --- Keycloak connection ---
    keycloak_url: str
    keycloak_realm: str = "master"
    keycloak_client_id: str
    keycloak_client_secret: SecretStr
    keycloak_scope: str = "openid profile email"

    # --- this app's own address, used to derive the callback/redirect URIs ---
    app_base_url: str
    post_login_redirect_path: str = "/"
    post_logout_redirect_path: str = "/"

    # --- session cookie (Starlette SessionMiddleware) ---
    session_secret_key: SecretStr
    session_cookie_name: str = "session"
    session_max_age_seconds: int | None = None
    session_https_only: bool = True

    # --- role extraction from Keycloak claims ---
    roles_source: Literal["realm", "resource", "both"] = "both"

    model_config = SettingsConfigDict(
        env_prefix="AUTH_",
        env_file=".env",
        extra="ignore",
    )