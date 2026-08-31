import secrets
from typing import Callable

import httpx
import jwt
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from .config import AuthSettings
from .keycloak import (
    build_authorize_url,
    build_end_session_url,
    discover,
    exchange_code_for_tokens,
    extract_roles,
    fetch_userinfo,
    read_access_token_claims,
    verify_id_token,
)

GetOrCreateUserFn = Callable[[dict], dict | None]


def create_auth_router(
    *,
    settings: AuthSettings,
    prefix: str = "/api/auth",
    get_or_create_user_fn: GetOrCreateUserFn | None = None,
) -> APIRouter:
    """Build a FastAPI router exposing Keycloak login/logout via a session.

    All four routes are `GET` — this is a browser-redirect flow, not a JSON
    API. No token is ever handed to the browser; the session cookie (set up
    separately via `configure_session`) is the only thing the client holds.

    Requires `SessionMiddleware` to already be attached to the app (see
    `configure_session`) — every route here reads/writes `request.session`.

    Args:
        settings: Loaded `AuthSettings`.
        prefix: URL prefix for the mounted routes. Also used to derive the
            callback URL registered with Keycloak
            (`{settings.app_base_url}{prefix}/callback`).
        get_or_create_user_fn: Optional callback `(claims: dict) -> dict | None`
            for syncing a local user record on login. `claims` is the
            verified id_token claims plus a `roles` key holding the same
            resolved role list that lands in the session. Enrichment only —
            Keycloak alone decides who can authenticate. If it returns
            `None`, login still succeeds; the session's `user` dict just
            has no `local` key.

    Returns:
        APIRouter with `/login`, `/callback`, `/logout`, `/me` under
        `prefix`. Mount with `app.include_router(...)`.
    """
    router = APIRouter(prefix=prefix, tags=["auth"])
    redirect_uri = f"{settings.app_base_url}{prefix}/callback"

    @router.get(
        "/login",
        summary="Redirect to Keycloak's login page",
        response_description="302 redirect to Keycloak's authorization endpoint.",
    )
    async def login(request: Request, prompt: str | None = None) -> RedirectResponse:
        """Start a Keycloak login: stash CSRF state in the session and redirect.

        Args:
            request: FastAPI request; `state` is stored on `request.session`.
            prompt: Optional OIDC `prompt` passthrough (e.g. `prompt=none`
                for a silent SSO probe from the SPA).

        Returns:
            302 redirect to Keycloak's authorization endpoint.
        """
        cfg = await discover(settings)
        state = secrets.token_urlsafe(24)
        request.session["oauth_state"] = state
        if prompt:
            request.session["oauth_silent"] = prompt == "none"
        return RedirectResponse(
            build_authorize_url(cfg, settings, redirect_uri=redirect_uri, state=state, prompt=prompt)
        )

    @router.get(
        "/callback",
        response_model=None,
        summary="Handle Keycloak's redirect back after login",
        response_description="302 redirect to the app's post-login path; session populated.",
        responses={
            401: {"description": "Missing/mismatched state, token exchange failure, or invalid id_token."},
        },
    )
    async def callback(
        request: Request,
        code: str | None = None,
        state: str | None = None,
        error: str | None = None,
    ):
        """Complete a Keycloak login and populate the session.

        Validates `state`, exchanges `code`, verifies the id_token, fetches
        userinfo, extracts roles (from the id_token claims, userinfo, and
        the unverified access token combined — Keycloak's default mapper
        config only puts roles in the access token), and (if provided) runs
        `get_or_create_user_fn` to attach a local record — never to block
        login. Access/refresh tokens are used server-side during
        `/callback` (userinfo call + role extraction) and then dropped, not
        persisted.

        Args:
            request: FastAPI request; `oauth_state`/`oauth_silent` read
                from and CSRF-checked against `request.session`.
            code: Authorization code query param.
            state: CSRF state query param.
            error: OIDC error query param, set by Keycloak instead of
                `code` when e.g. a silent (`prompt=none`) probe finds no
                existing SSO session.

        Returns:
            302 redirect to `settings.post_login_redirect_path` on success.
            A JSON 401 response on failure (or a silent redirect home, for
            a failed silent-SSO probe).
        """
        silent = request.session.pop("oauth_silent", False)
        if error:
            if silent:
                return RedirectResponse(settings.app_base_url + settings.post_login_redirect_path)
            return JSONResponse({"detail": error}, status_code=401)
        if not code or not state or state != request.session.get("oauth_state"):
            return JSONResponse({"detail": "Invalid or missing state"}, status_code=401)

        cfg = await discover(settings)
        try:
            tokens = await exchange_code_for_tokens(cfg, settings, code=code, redirect_uri=redirect_uri)
        except httpx.HTTPStatusError:
            return JSONResponse({"detail": "Token exchange failed"}, status_code=401)

        try:
            claims = verify_id_token(settings, tokens["id_token"])
        except jwt.ExpiredSignatureError:
            return JSONResponse({"detail": "id_token has expired"}, status_code=401)
        except jwt.InvalidTokenError:
            return JSONResponse({"detail": "Invalid id_token"}, status_code=401)

        access_token = tokens.get("access_token", "")
        userinfo = await fetch_userinfo(cfg, access_token)
        access_claims = read_access_token_claims(access_token) if access_token else {}
        # Keycloak's stock "roles" client scope mapper ships with "Add to
        # access token" on but "Add to ID token"/"Add to userinfo" off by
        # default, and it's common for a client to have only one of the
        # latter two enabled. Feed all three sources to extract_roles() so
        # roles get picked up wherever the realm actually put them —
        # including the access token, which is the only place a fully
        # default client emits them — instead of requiring every consumer
        # to notice and fix a specific mapper checkbox before role-based
        # auth silently denies everyone.
        roles = extract_roles(settings, claims, userinfo, access_claims)
        # The fn's contract is "verified identity + resolved roles"; hand it
        # the same role list that lands in the session, not the bare
        # id_token claims (which, per the above, often carry no roles).
        local = get_or_create_user_fn({**claims, "roles": roles}) if get_or_create_user_fn else None

        user = {
            "sub": claims["sub"],
            "preferred_username": userinfo.get("preferred_username") or claims.get("preferred_username"),
            "email": userinfo.get("email") or claims.get("email"),
            "name": userinfo.get("name") or claims.get("name"),
            "roles": roles,
        }
        if local is not None:
            user["local"] = local

        request.session["user"] = user
        request.session["id_token"] = tokens.get("id_token")
        request.session.pop("oauth_state", None)

        return RedirectResponse(settings.app_base_url + settings.post_login_redirect_path)

    @router.get(
        "/logout",
        summary="Clear the session and end the Keycloak SSO session",
        response_description="302 redirect to Keycloak's end-session endpoint (or the app's post-logout path).",
    )
    async def logout(request: Request) -> RedirectResponse:
        """Clear the local session and redirect to Keycloak's RP-initiated logout.

        Args:
            request: FastAPI request; session is read then cleared.

        Returns:
            302 redirect to `end_session_endpoint` (ends Keycloak's SSO
            session too) if the realm advertises one, else a redirect to
            `settings.post_logout_redirect_path`.
        """
        cfg = await discover(settings)
        id_token = request.session.get("id_token")
        request.session.clear()

        end_session_url = build_end_session_url(
            cfg,
            post_logout_redirect_uri=settings.app_base_url + settings.post_logout_redirect_path,
            id_token=id_token,
        )
        return RedirectResponse(end_session_url or (settings.app_base_url + settings.post_logout_redirect_path))

    @router.get(
        "/me",
        response_model=None,
        summary="Return the current session's authentication state",
    )
    def me(request: Request) -> dict:
        """Report whether the caller has an authenticated session.

        Args:
            request: FastAPI request; reads `request.session["user"]`.

        Returns:
            `{"authenticated": False}`, or
            `{"authenticated": True, "user": {...}}` with the dict stored
            at login time (`sub`, `preferred_username`, `email`, `name`,
            `roles`, optional `local`).
        """
        user = request.session.get("user")
        if user is None:
            return {"authenticated": False}
        return {"authenticated": True, "user": user}

    return router