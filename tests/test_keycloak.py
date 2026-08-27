import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from auth import AuthSettings
from auth import keycloak
from auth.keycloak import build_authorize_url, extract_roles, verify_id_token


@pytest.fixture(autouse=True)
def _clear_discovery_cache():
    keycloak._discovery_cache.clear()
    yield
    keycloak._discovery_cache.clear()


@pytest.fixture(scope="module")
def rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


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


def _sign_id_token(private_pem, *, issuer, audience, sub="alice", exp_delta=timedelta(minutes=5)):
    payload = {
        "sub": sub,
        "iss": issuer,
        "aud": audience,
        "exp": datetime.now(timezone.utc) + exp_delta,
        "realm_access": {"roles": ["admin"]},
        "preferred_username": sub,
    }
    return jwt.encode(payload, private_pem, algorithm="RS256")


class TestVerifyIdToken:
    def test_happy_path(self, auth_settings, rsa_keys):
        private_pem, public_pem = rsa_keys
        issuer = f"{auth_settings.keycloak_url}/realms/{auth_settings.keycloak_realm}"
        token = _sign_id_token(private_pem, issuer=issuer, audience=auth_settings.keycloak_client_id)

        with patch("auth.keycloak._jwks_client") as mock_jwks_client:
            mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = MagicMock(key=public_pem)
            claims = verify_id_token(auth_settings, token)

        assert claims["sub"] == "alice"
        assert claims["realm_access"]["roles"] == ["admin"]

    def test_expired_token(self, auth_settings, rsa_keys):
        private_pem, public_pem = rsa_keys
        issuer = f"{auth_settings.keycloak_url}/realms/{auth_settings.keycloak_realm}"
        token = _sign_id_token(
            private_pem, issuer=issuer, audience=auth_settings.keycloak_client_id, exp_delta=timedelta(minutes=-5)
        )

        with patch("auth.keycloak._jwks_client") as mock_jwks_client:
            mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = MagicMock(key=public_pem)
            with pytest.raises(jwt.ExpiredSignatureError):
                verify_id_token(auth_settings, token)

    def test_wrong_audience(self, auth_settings, rsa_keys):
        private_pem, public_pem = rsa_keys
        issuer = f"{auth_settings.keycloak_url}/realms/{auth_settings.keycloak_realm}"
        token = _sign_id_token(private_pem, issuer=issuer, audience="someone-else")

        with patch("auth.keycloak._jwks_client") as mock_jwks_client:
            mock_jwks_client.return_value.get_signing_key_from_jwt.return_value = MagicMock(key=public_pem)
            with pytest.raises(jwt.InvalidTokenError):
                verify_id_token(auth_settings, token)


class TestDiscover:
    def test_caches_by_issuer(self, auth_settings, monkeypatch):
        calls = {"n": 0}

        class _Resp:
            def raise_for_status(self):
                pass

            def json(self):
                return {"authorization_endpoint": "https://kc.example.com/auth"}

        class _FakeAsyncClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def get(self, url):
                calls["n"] += 1
                return _Resp()

        monkeypatch.setattr(keycloak.httpx, "AsyncClient", lambda: _FakeAsyncClient())

        cfg1 = asyncio.run(keycloak.discover(auth_settings))
        cfg2 = asyncio.run(keycloak.discover(auth_settings))

        assert cfg1 == cfg2
        assert calls["n"] == 1

    def test_refetches_after_ttl_expires(self, auth_settings, monkeypatch):
        calls = {"n": 0}

        class _Resp:
            def raise_for_status(self):
                pass

            def json(self):
                return {"authorization_endpoint": "https://kc.example.com/auth"}

        class _FakeAsyncClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc):
                return False

            async def get(self, url):
                calls["n"] += 1
                return _Resp()

        monkeypatch.setattr(keycloak.httpx, "AsyncClient", lambda: _FakeAsyncClient())

        fake_now = {"t": 1000.0}
        monkeypatch.setattr(keycloak.time, "monotonic", lambda: fake_now["t"])

        asyncio.run(keycloak.discover(auth_settings))
        assert calls["n"] == 1

        fake_now["t"] += keycloak._DISCOVERY_TTL_SECONDS - 1
        asyncio.run(keycloak.discover(auth_settings))
        assert calls["n"] == 1, "still within TTL, should not re-fetch"

        fake_now["t"] += 2
        asyncio.run(keycloak.discover(auth_settings))
        assert calls["n"] == 2, "past TTL, should re-fetch"


class TestBuildAuthorizeUrl:
    _cfg = {"authorization_endpoint": "https://kc.example.com/realms/testrealm/protocol/openid-connect/auth"}

    def test_includes_required_params(self, auth_settings):
        url = build_authorize_url(
            self._cfg, auth_settings, redirect_uri="https://app.example.com/api/auth/callback", state="s123"
        )
        qs = parse_qs(urlparse(url).query)
        assert qs["client_id"] == [auth_settings.keycloak_client_id]
        assert qs["redirect_uri"] == ["https://app.example.com/api/auth/callback"]
        assert qs["scope"] == [auth_settings.keycloak_scope]
        assert qs["state"] == ["s123"]
        assert "prompt" not in qs

    def test_prompt_only_present_when_passed(self, auth_settings):
        url = build_authorize_url(
            self._cfg,
            auth_settings,
            redirect_uri="https://app.example.com/api/auth/callback",
            state="s123",
            prompt="none",
        )
        qs = parse_qs(urlparse(url).query)
        assert qs["prompt"] == ["none"]


class TestExtractRoles:
    _claims = {
        "realm_access": {"roles": ["admin", "staff"]},
        "resource_access": {"my-client": {"roles": ["staff", "editor"]}},
    }

    def test_both_sources_union_and_dedupe(self, auth_settings):
        settings = auth_settings.model_copy(update={"roles_source": "both"})
        assert extract_roles(settings, self._claims) == ["admin", "editor", "staff"]

    def test_realm_only(self, auth_settings):
        settings = auth_settings.model_copy(update={"roles_source": "realm"})
        assert extract_roles(settings, self._claims) == ["admin", "staff"]

    def test_resource_only(self, auth_settings):
        settings = auth_settings.model_copy(update={"roles_source": "resource"})
        assert extract_roles(settings, self._claims) == ["editor", "staff"]

    def test_no_roles_claims_returns_empty(self, auth_settings):
        assert extract_roles(auth_settings, {"sub": "alice"}) == []