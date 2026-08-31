from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from auth import AuthSettings, configure_session, create_auth_router, make_require_roles

MOCK_CFG = {
    "authorization_endpoint": "https://kc.example.com/realms/testrealm/protocol/openid-connect/auth",
    "token_endpoint": "https://kc.example.com/realms/testrealm/protocol/openid-connect/token",
    "userinfo_endpoint": "https://kc.example.com/realms/testrealm/protocol/openid-connect/userinfo",
    "end_session_endpoint": "https://kc.example.com/realms/testrealm/protocol/openid-connect/logout",
}


@pytest.fixture
def auth_settings() -> AuthSettings:
    return AuthSettings(
        keycloak_url="https://kc.example.com",
        keycloak_realm="testrealm",
        keycloak_client_id="my-client",
        keycloak_client_secret="shh",
        app_base_url="https://app.example.com",
        session_secret_key="session-secret",
        session_https_only=False,
    )


@pytest.fixture(autouse=True)
def _mock_discover(monkeypatch):
    async def _discover(settings):
        return MOCK_CFG

    monkeypatch.setattr("auth.router.discover", _discover)


def _make_app(settings, get_or_create_user_fn=None) -> FastAPI:
    app = FastAPI()
    configure_session(app, settings)
    app.include_router(create_auth_router(settings=settings, get_or_create_user_fn=get_or_create_user_fn))
    return app


def _login_and_get_state(client: TestClient) -> str:
    resp = client.get("/api/auth/login", follow_redirects=False)
    location = resp.headers["location"]
    return parse_qs(urlparse(location).query)["state"][0]


def _claims(sub="alice", roles=("admin",)):
    return {"sub": sub, "preferred_username": sub, "realm_access": {"roles": list(roles)}}


def test_login_redirects_to_authorization_endpoint(auth_settings):
    client = TestClient(_make_app(auth_settings))

    resp = client.get("/api/auth/login", follow_redirects=False)

    assert resp.status_code in (302, 307)
    location = resp.headers["location"]
    assert location.startswith(MOCK_CFG["authorization_endpoint"])
    assert "state=" in location


def test_login_prompt_none_then_callback_error_redirects_silently(auth_settings):
    client = TestClient(_make_app(auth_settings))
    client.get("/api/auth/login", params={"prompt": "none"}, follow_redirects=False)

    resp = client.get("/api/auth/callback", params={"error": "login_required"}, follow_redirects=False)

    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == auth_settings.app_base_url + auth_settings.post_login_redirect_path


def test_callback_missing_code_401(auth_settings):
    client = TestClient(_make_app(auth_settings))
    state = _login_and_get_state(client)

    resp = client.get("/api/auth/callback", params={"state": state})
    assert resp.status_code == 401


def test_callback_state_mismatch_401(auth_settings):
    client = TestClient(_make_app(auth_settings))
    _login_and_get_state(client)

    resp = client.get("/api/auth/callback", params={"code": "abc", "state": "wrong"})
    assert resp.status_code == 401


def test_callback_token_exchange_failure_401(auth_settings, monkeypatch):
    client = TestClient(_make_app(auth_settings))
    state = _login_and_get_state(client)

    error = httpx.HTTPStatusError("boom", request=MagicMock(), response=MagicMock())
    monkeypatch.setattr("auth.router.exchange_code_for_tokens", AsyncMock(side_effect=error))

    resp = client.get("/api/auth/callback", params={"code": "abc", "state": state})
    assert resp.status_code == 401


def test_callback_invalid_id_token_401(auth_settings, monkeypatch):
    client = TestClient(_make_app(auth_settings))
    state = _login_and_get_state(client)

    monkeypatch.setattr(
        "auth.router.exchange_code_for_tokens",
        AsyncMock(return_value={"id_token": "x", "access_token": "y"}),
    )
    monkeypatch.setattr("auth.router.verify_id_token", MagicMock(side_effect=jwt.InvalidTokenError("bad sig")))

    resp = client.get("/api/auth/callback", params={"code": "abc", "state": state})
    assert resp.status_code == 401


def test_callback_happy_path_populates_session_and_redirects(auth_settings, monkeypatch):
    client = TestClient(_make_app(auth_settings))
    state = _login_and_get_state(client)

    monkeypatch.setattr(
        "auth.router.exchange_code_for_tokens",
        AsyncMock(return_value={"id_token": "x", "access_token": "y"}),
    )
    monkeypatch.setattr("auth.router.verify_id_token", MagicMock(return_value=_claims()))
    monkeypatch.setattr("auth.router.fetch_userinfo", AsyncMock(return_value={"email": "alice@example.com"}))

    resp = client.get("/api/auth/callback", params={"code": "abc", "state": state}, follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == auth_settings.app_base_url + auth_settings.post_login_redirect_path

    body = client.get("/api/auth/me").json()
    assert body["authenticated"] is True
    assert body["user"]["sub"] == "alice"
    assert body["user"]["roles"] == ["admin"]
    assert body["user"]["email"] == "alice@example.com"
    assert "local" not in body["user"]


def test_callback_picks_up_roles_missing_from_id_token_but_present_in_userinfo(auth_settings, monkeypatch):
    """Keycloak's default 'roles' mapper often adds roles to only one of
    id_token/userinfo — a client with only 'Add to userinfo' enabled (and
    not 'Add to ID token') must still end up with roles in the session."""
    client = TestClient(_make_app(auth_settings))
    state = _login_and_get_state(client)

    claims_without_roles = {"sub": "alice", "preferred_username": "alice"}
    monkeypatch.setattr(
        "auth.router.exchange_code_for_tokens",
        AsyncMock(return_value={"id_token": "x", "access_token": "y"}),
    )
    monkeypatch.setattr("auth.router.verify_id_token", MagicMock(return_value=claims_without_roles))
    monkeypatch.setattr(
        "auth.router.fetch_userinfo",
        AsyncMock(return_value={"realm_access": {"roles": ["admin"]}}),
    )

    client.get("/api/auth/callback", params={"code": "abc", "state": state}, follow_redirects=False)

    body = client.get("/api/auth/me").json()
    assert body["user"]["roles"] == ["admin"]


def test_callback_picks_up_roles_only_in_access_token(auth_settings, monkeypatch):
    """A fully default Keycloak client emits realm/client roles ONLY in the
    access token (not id_token, not userinfo) — they must still reach the
    session."""
    client = TestClient(_make_app(auth_settings))
    state = _login_and_get_state(client)

    access_token = jwt.encode(
        {"realm_access": {"roles": ["admin"]}}, "x" * 32, algorithm="HS256"
    )
    monkeypatch.setattr(
        "auth.router.exchange_code_for_tokens",
        AsyncMock(return_value={"id_token": "x", "access_token": access_token}),
    )
    monkeypatch.setattr(
        "auth.router.verify_id_token",
        MagicMock(return_value={"sub": "alice", "preferred_username": "alice"}),
    )
    monkeypatch.setattr("auth.router.fetch_userinfo", AsyncMock(return_value={}))

    client.get("/api/auth/callback", params={"code": "abc", "state": state}, follow_redirects=False)

    body = client.get("/api/auth/me").json()
    assert body["user"]["roles"] == ["admin"]


def test_callback_enriches_with_get_or_create_user_fn(auth_settings, monkeypatch):
    seen = {}

    def _fn(claims):
        seen.update(claims)
        return {"mongo_id": "abc123"}

    client = TestClient(_make_app(auth_settings, get_or_create_user_fn=_fn))
    state = _login_and_get_state(client)

    monkeypatch.setattr(
        "auth.router.exchange_code_for_tokens",
        AsyncMock(return_value={"id_token": "x", "access_token": "y"}),
    )
    monkeypatch.setattr("auth.router.verify_id_token", MagicMock(return_value=_claims()))
    monkeypatch.setattr("auth.router.fetch_userinfo", AsyncMock(return_value={}))

    client.get("/api/auth/callback", params={"code": "abc", "state": state}, follow_redirects=False)

    body = client.get("/api/auth/me").json()
    assert body["user"]["local"] == {"mongo_id": "abc123"}
    # the fn sees resolved roles alongside the id_token claims, not bare claims
    assert seen["roles"] == ["admin"]
    assert seen["sub"] == "alice"


def test_callback_login_succeeds_when_user_sync_returns_none(auth_settings, monkeypatch):
    """Keycloak alone gates login — an unmatched local record must not block it."""
    client = TestClient(_make_app(auth_settings, get_or_create_user_fn=lambda claims: None))
    state = _login_and_get_state(client)

    monkeypatch.setattr(
        "auth.router.exchange_code_for_tokens",
        AsyncMock(return_value={"id_token": "x", "access_token": "y"}),
    )
    monkeypatch.setattr("auth.router.verify_id_token", MagicMock(return_value=_claims()))
    monkeypatch.setattr("auth.router.fetch_userinfo", AsyncMock(return_value={}))

    resp = client.get("/api/auth/callback", params={"code": "abc", "state": state}, follow_redirects=False)
    assert resp.status_code in (302, 307)

    body = client.get("/api/auth/me").json()
    assert body["authenticated"] is True
    assert "local" not in body["user"]


def test_me_unauthenticated_returns_false(auth_settings):
    client = TestClient(_make_app(auth_settings))

    resp = client.get("/api/auth/me")
    assert resp.status_code == 200
    assert resp.json() == {"authenticated": False}


def test_logout_clears_session_and_redirects_with_id_token_hint(auth_settings, monkeypatch):
    client = TestClient(_make_app(auth_settings))
    state = _login_and_get_state(client)

    monkeypatch.setattr(
        "auth.router.exchange_code_for_tokens",
        AsyncMock(return_value={"id_token": "id-tok-value", "access_token": "y"}),
    )
    monkeypatch.setattr("auth.router.verify_id_token", MagicMock(return_value=_claims()))
    monkeypatch.setattr("auth.router.fetch_userinfo", AsyncMock(return_value={}))
    client.get("/api/auth/callback", params={"code": "abc", "state": state}, follow_redirects=False)

    resp = client.get("/api/auth/logout", follow_redirects=False)
    assert resp.status_code in (302, 307)
    location = resp.headers["location"]
    assert location.startswith(MOCK_CFG["end_session_endpoint"])
    assert "id_token_hint=id-tok-value" in location

    assert client.get("/api/auth/me").json() == {"authenticated": False}


def _make_protected_app(settings: AuthSettings) -> FastAPI:
    app = FastAPI()
    configure_session(app, settings)
    require_roles = make_require_roles(settings)

    @app.post("/seed-session")
    def seed_session(request: Request, payload: dict) -> dict:
        request.session["user"] = payload
        return {"ok": True}

    @app.get("/admin-only")
    def admin_only(user: dict = Depends(require_roles(["admin"]))) -> dict:
        return {"user": user}

    @app.get("/whoami")
    def whoami(user: dict = Depends(require_roles.get_current_claims)) -> dict:
        return {"user": user}

    return app


def test_require_roles_401_no_session(auth_settings):
    client = TestClient(_make_protected_app(auth_settings))

    resp = client.get("/admin-only")
    assert resp.status_code == 401


def test_require_roles_allow(auth_settings):
    client = TestClient(_make_protected_app(auth_settings))
    client.post("/seed-session", json={"sub": "alice", "roles": ["admin"]})

    resp = client.get("/admin-only")
    assert resp.status_code == 200
    assert resp.json()["user"]["sub"] == "alice"


def test_require_roles_deny(auth_settings):
    client = TestClient(_make_protected_app(auth_settings))
    client.post("/seed-session", json={"sub": "bob", "roles": ["staff"]})

    resp = client.get("/admin-only")
    assert resp.status_code == 403


def test_get_current_claims(auth_settings):
    client = TestClient(_make_protected_app(auth_settings))
    client.post("/seed-session", json={"sub": "carol", "roles": []})

    resp = client.get("/whoami")
    assert resp.status_code == 200
    assert resp.json()["user"]["sub"] == "carol"