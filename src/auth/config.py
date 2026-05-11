from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthSettings(BaseSettings):
    jwt_secret_key: SecretStr
    jwt_algorithm: str = "HS256"

    access_ttl_minutes: int = 480
    refresh_ttl_minutes: int = 1440

    refresh_cookie_path: str = "/api/auth/refresh"
    secure_cookie: bool = True
    cookie_samesite: Literal["strict", "lax", "none"] = "strict"

    pepper_secret: SecretStr

    model_config = SettingsConfigDict(
        env_prefix="AUTH_",
        env_file=".env",
        extra="ignore",
    )