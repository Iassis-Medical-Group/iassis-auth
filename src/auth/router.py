from typing import Callable

import jwt
from fastapi import APIRouter, HTTPException, Request, Response

from .config import AuthSettings
from .models import ErrorResponse, InLogin, TokenResponse, UserRecord
from .security import (
    PasswordHasher,
    create_access_token,
    create_refresh_token,
    decode_token,
)


GetUserFn = Callable[[str], UserRecord | None]


def create_auth_router(
    *,
    settings: AuthSettings,
    hasher: PasswordHasher,
    get_user_fn: GetUserFn,
    prefix: str = "/api/auth",
) -> APIRouter:
    """Build a FastAPI router exposing `/login`, `/refresh`, and `/logout`.

    The library performs no DB I/O itself — `get_user_fn` is what knows
    where users live and how to read them. Return `None` when the user
    does not exist; the router handles the constant-time decoy.

    Args:
        settings: Loaded `AuthSettings` (env-driven). Provides JWT secret,
            algorithm, TTLs, cookie config.
        hasher: A `PasswordHasher` built via `make_password_hasher(settings)`.
            Carries the deployment pepper.
        get_user_fn: Callback `(identity: str) -> UserRecord | None`.
            Consumer-supplied; queries the user collection and adapts the
            document into `UserRecord`.
        prefix: URL prefix for the mounted routes. Defaults to `/api/auth`.

    Returns:
        APIRouter with three endpoints under `prefix`. Mount with
        `app.include_router(...)`.
    """
    router = APIRouter(prefix=prefix, tags=["auth"])

    @router.post(
        "/login",
        response_model=TokenResponse,
        status_code=200,
        summary="Authenticate user and issue tokens",
        response_description="Access token in body; refresh token set as HttpOnly cookie.",
        responses={
            401: {
                "model": ErrorResponse,
                "description": "Invalid credentials or unknown user.",
            },
            403: {
                "model": ErrorResponse,
                "description": "Account is disabled (`is_active=False`).",
            },
        },
    )
    def login(body: InLogin, response: Response) -> TokenResponse:
        """Verify credentials and issue an access + refresh token pair.

        On success:
            * Sets `refresh_token` as an HttpOnly, SameSite=Strict cookie
              scoped to `AUTH_REFRESH_COOKIE_PATH`.
            * Returns the access token in the response body.

        Constant-time decoy hashing runs on the missing-user path so that
        wrong-username and wrong-password requests take equivalent wall-
        clock time, preventing username enumeration.

        Args:
            body: JSON body with `username` and `password`.
            response: FastAPI response object used to set the cookie.

        Returns:
            `TokenResponse` containing the short-lived access token.

        Raises:
            HTTPException 401: Unknown user or wrong password.
            HTTPException 403: User exists but `is_active=False`.
        """
        user = get_user_fn(body.username)
        if user is None or not user.is_active:
            hasher.dummy_verify()
            raise HTTPException(status_code=401, detail="Unauthorized")
        if not hasher.verify(body.password, user.password_hash):
            raise HTTPException(status_code=401, detail="Unauthorized")

        refresh_token = create_refresh_token(settings, user.identity, user.roles)
        response.set_cookie(
            key="refresh_token",
            value=refresh_token,
            httponly=True,
            secure=settings.secure_cookie,
            samesite=settings.cookie_samesite,
            max_age=settings.refresh_ttl_minutes * 60,
            path=settings.refresh_cookie_path,
        )
        access_token = create_access_token(
            settings, user.identity, user.roles, user.extra_claims
        )
        return TokenResponse(token=access_token)

    @router.post(
        "/refresh",
        response_model=TokenResponse,
        status_code=200,
        summary="Mint a new access token from the refresh cookie",
        response_description="New access token in the response body.",
        responses={
            401: {
                "model": ErrorResponse,
                "description": (
                    "Refresh cookie missing, invalid, expired, of the wrong "
                    "token type, or user is no longer active."
                ),
            },
        },
    )
    def refresh(request: Request) -> TokenResponse:
        """Exchange a valid refresh cookie for a new access token.

        The refresh cookie is signed with the same secret as access tokens
        but carries `type=refresh`. This endpoint:

            1. Reads the `refresh_token` cookie.
            2. Verifies signature, expiry, and `type=refresh`.
            3. Re-fetches the user via `get_user_fn` (so a disabled user
               cannot keep refreshing with an old role set).
            4. Mints a new access token with the user's current roles and
               `extra_claims`.

        Args:
            request: FastAPI request; cookie is read from `request.cookies`.

        Returns:
            `TokenResponse` with a freshly-minted access token.

        Raises:
            HTTPException 401: Missing/invalid/expired refresh token, wrong
                token type, or the user is no longer active.
        """
        token = request.cookies.get("refresh_token")
        if not token:
            raise HTTPException(status_code=401, detail="Missing refresh token")

        try:
            payload = decode_token(settings, token)
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Refresh token has expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")

        identity = payload["sub"]
        user = get_user_fn(identity)
        if user is None or not user.is_active:
            raise HTTPException(status_code=401, detail="Unauthorized")

        access_token = create_access_token(
            settings, user.identity, user.roles, user.extra_claims
        )
        return TokenResponse(token=access_token)

    @router.post(
        "/logout",
        status_code=200,
        summary="Clear the refresh cookie",
        response_description="`{ msg: 'Logout successful' }`",
    )
    def logout(response: Response) -> dict:
        """Delete the `refresh_token` cookie.

        Access tokens are not revoked server-side — the client must drop
        the access token from memory separately. Once the refresh cookie
        is gone, the client cannot mint new access tokens.

        Args:
            response: FastAPI response object used to clear the cookie.

        Returns:
            A confirmation message.
        """
        response.delete_cookie(
            key="refresh_token", path=settings.refresh_cookie_path
        )
        return {"msg": "Logout successful"}

    return router