"""Keycloak OIDC protocol primitives.

Framework-thin: every function takes `AuthSettings` explicitly and does
one thing (discover, build a URL, exchange a code, verify a token). The
actual FastAPI routes live in `router.py`, which composes these.
"""
import jwt
import time
import httpx

from .config import AuthSettings
from urllib.parse import urlencode

# Keyed by issuer URL rather than a single global dict, so a process that
# ever builds more than one AuthSettings (e.g. tests) doesn't cross-pollute.
_discovery_cache: dict[str, tuple[float, dict]] = {}
_DISCOVERY_TTL_SECONDS = 300  # 5 minutes

def _issuer(settings: AuthSettings) -> str:
    return f"{settings.keycloak_url}/realms/{settings.keycloak_realm}"


def _jwks_client(settings: AuthSettings) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(f"{_issuer(settings)}/protocol/openid-connect/certs")


async def discover(settings: AuthSettings) -> dict:
    """Fetch and cache the realm's OIDC discovery document.

    Cached per issuer URL for up to `_DISCOVERY_TTL_SECONDS`; a stale
    entry triggers exactly one re-fetch on the next call.

    Args:
        settings: Loaded `AuthSettings`.

    Returns:
        The discovery document (`authorization_endpoint`, `token_endpoint`,
        `userinfo_endpoint`, `end_session_endpoint`, etc).
    """
    issuer = _issuer(settings)
    cached = _discovery_cache.get(issuer)
    if cached is not None:
        fetched_at, doc = cached
        if time.monotonic() - fetched_at < _DISCOVERY_TTL_SECONDS:
            return doc

    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{issuer}/.well-known/openid-configuration")
        resp.raise_for_status()
        doc = resp.json()

    _discovery_cache[issuer] = (time.monotonic(), doc)
    return doc


def build_authorize_url(
    cfg: dict,
    settings: AuthSettings,
    *,
    redirect_uri: str,
    state: str,
    prompt: str | None = None,
) -> str:
    """Build the URL to redirect the browser to for a Keycloak login.

    Args:
        cfg: Discovery document from `discover()`.
        settings: Loaded `AuthSettings`.
        redirect_uri: This app's callback URL, as registered in Keycloak.
        state: Opaque CSRF token; caller stashes it in the session and
            compares it against `/callback`'s `state` query param.
        prompt: Optional OIDC `prompt` value (e.g. `"none"` for a silent
            SSO probe).

    Returns:
        Full authorization-endpoint URL with query params set.
    """
    params = {
        "client_id": settings.keycloak_client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": settings.keycloak_scope,
        "state": state,
    }
    if prompt:
        params["prompt"] = prompt
    return f"{cfg['authorization_endpoint']}?{urlencode(params)}"


async def exchange_code_for_tokens(
    cfg: dict,
    settings: AuthSettings,
    *,
    code: str,
    redirect_uri: str,
) -> dict:
    """Exchange an authorization code for Keycloak's token response.

    Uses `client_secret_post` (client_id/secret in the POST body), matching
    a standard confidential Keycloak client.

    Args:
        cfg: Discovery document from `discover()`.
        settings: Loaded `AuthSettings`.
        code: Authorization code from the `/callback` query params.
        redirect_uri: Must exactly match the one used to build the
            authorize URL.

    Returns:
        Decoded JSON token response (`access_token`, `id_token`, etc).

    Raises:
        httpx.HTTPStatusError: Token endpoint returned a non-2xx status
            (expired/invalid code, redirect_uri mismatch, etc).
    """
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            cfg["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": settings.keycloak_client_id,
                "client_secret": settings.keycloak_client_secret.get_secret_value(),
            },
        )
        resp.raise_for_status()
        return resp.json()


async def fetch_userinfo(cfg: dict, access_token: str) -> dict:
    """Fetch userinfo claims for the current access token.

    Args:
        cfg: Discovery document from `discover()`.
        access_token: Access token from `exchange_code_for_tokens()`.

    Returns:
        Userinfo claims dict, or `{}` if the endpoint didn't return 200.
    """
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            cfg["userinfo_endpoint"],
            headers={"Authorization": f"Bearer {access_token}"},
        )
    return resp.json() if resp.status_code == 200 else {}


def verify_id_token(settings: AuthSettings, id_token: str) -> dict:
    """Verify a Keycloak id_token's signature and standard claims.

    OIDC id_tokens are spec-guaranteed to carry `aud=client_id`, so this
    uses plain `audience=` checking with no `azp`-fallback.

    Args:
        settings: Loaded `AuthSettings`.
        id_token: Raw id_token string from the token endpoint response.

    Returns:
        Decoded claims dict.

    Raises:
        jwt.ExpiredSignatureError: Token `exp` is in the past.
        jwt.InvalidTokenError: Signature, issuer, or audience mismatch.
    """
    issuer = _issuer(settings)
    signing_key = _jwks_client(settings).get_signing_key_from_jwt(id_token)
    return jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        issuer=issuer,
        audience=settings.keycloak_client_id,
    )


def build_end_session_url(
    cfg: dict,
    *,
    post_logout_redirect_uri: str,
    id_token: str | None,
) -> str | None:
    """Build Keycloak's RP-initiated-logout URL, if the realm supports it.

    Args:
        cfg: Discovery document from `discover()`.
        post_logout_redirect_uri: Where Keycloak should send the browser
            back to after ending its own SSO session.
        id_token: The id_token from login, if still held in the session.
            Passed as `id_token_hint` when available.

    Returns:
        Full `end_session_endpoint` URL, or `None` if the realm's
        discovery document doesn't advertise one.
    """
    end_session: str | None = cfg.get("end_session_endpoint")
    if end_session is None:
        return None
    params = {"post_logout_redirect_uri": post_logout_redirect_uri}
    if id_token:
        params["id_token_hint"] = id_token
    return f"{end_session}?{urlencode(params)}"


def read_access_token_claims(access_token: str) -> dict:
    """Decode a Keycloak access token WITHOUT verifying its signature.

    Only ever called on the `access_token` that arrives in the same token
    endpoint response as an id_token this library has already fully
    verified (`verify_id_token`) — same TLS response, same issuer, so the
    transport trust is already established. Skipping re-verification here
    avoids a second JWKS fetch on every login.

    Why bother reading it at all: Keycloak's stock "roles" client scope
    ships with its mappers set to "Add to access token" ON but "Add to ID
    token"/"Add to userinfo" OFF, so on a default client `realm_access` /
    `resource_access` appear ONLY in the access token. Feeding this dict to
    `extract_roles` alongside the id_token/userinfo claims makes role-based
    auth work with no Keycloak mapper change.

    Args:
        access_token: The raw access token string from
            `exchange_code_for_tokens()`.

    Returns:
        The token's claims, or `{}` if it isn't a decodable JWT (e.g. an
        IdP that issues opaque access tokens).
    """
    try:
        return jwt.decode(access_token, options={"verify_signature": False})
    except jwt.InvalidTokenError:
        return {}


def extract_roles(settings: AuthSettings, *claim_sources: dict) -> list[str]:
    """Pull role names out of one or more Keycloak claim dicts.

    Realm roles live at `claims["realm_access"]["roles"]`; client roles for
    this app's own client live at
    `claims["resource_access"][settings.keycloak_client_id]["roles"]`.
    Depending on which of the "roles" client scope's mappers are enabled,
    those can show up in the id_token, in userinfo, in the access token, or
    only some of them — so this accepts several claim dicts and unions the
    roles found in each. Pass the verified id_token claims, the userinfo
    response, and `read_access_token_claims(access_token)` together.

    Roles listed in `settings.roles_exclude` (default: Keycloak's stock
    `offline_access` / `uma_authorization`, always plus the realm's
    `default-roles-<realm>` composite) are stripped from the result — those
    ride along in `realm_access.roles` on every login and are never
    meaningful app roles.

    Args:
        settings: Loaded `AuthSettings`. `roles_source` picks which of the
            two claim locations to read; `roles_exclude` filters the result.
        *claim_sources: One or more claim dicts (verified id_token claims,
            userinfo, decoded access token). Missing keys are ignored, so
            passing `{}` is harmless.

    Returns:
        Sorted, deduplicated list of role names, minus the excluded set.
        Empty if none are present in any source (in which case none of the
        mappers above put roles anywhere this library can read).
    """
    roles: set[str] = set()
    for claims in claim_sources:
        if settings.roles_source in ("realm", "both"):
            roles |= set(claims.get("realm_access", {}).get("roles", []))
        if settings.roles_source in ("resource", "both"):
            resource = claims.get("resource_access", {}).get(settings.keycloak_client_id, {})
            roles |= set(resource.get("roles", []))
    return sorted(roles - settings.roles_exclude_set)