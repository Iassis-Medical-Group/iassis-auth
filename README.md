# iassis-auth

Shared FastAPI authentication library for IASSIS Medical Group internal services.

Keycloak is the identity provider. This library is a thin, reusable
FastAPI "BFF" (backend-for-frontend) layer around Keycloak's OIDC
Authorization Code flow: it redirects the browser to Keycloak to log in,
exchanges the code server-side, and holds the result in an
itsdangerous-signed Starlette session cookie. **No password is ever
stored by this library, and no token is ever handed to the browser** —
the session cookie is the only thing the client holds.

---

## Features

- **Keycloak login / callback / logout**, mirroring the standard
  Authorization Code (confidential client) flow — no PKCE, no client
  secret in the browser.
- **Starlette signed-cookie session** (`itsdangerous`) — no database, no
  server-side session store. `configure_session(app, settings)` wires it
  up with sane defaults.
- **Role-based dependencies** (`require_roles(["admin"])`), reading roles
  out of the session's Keycloak claims rather than decoding a bearer JWT.
- **RP-initiated logout** — `/logout` ends this app's session *and*
  redirects through Keycloak's `end_session_endpoint`, so the realm-wide
  SSO session ends too.
- **Optional local-user enrichment hook** (`get_or_create_user_fn`) for
  syncing a Keycloak login to your own DB record — never a login gate;
  Keycloak alone decides who can authenticate.
- **No database I/O of its own.** Same as before: the library only knows
  how to talk to Keycloak and manage the session; your app's routes decide
  what an authenticated session can access.

---

## Installation

Three install paths depending on where you are in the release cycle.

### 1. Production / shared services — tagged release (preferred)

Once a `vX.Y.Z` tag exists on the internal GitHub repo, pin it in your consumer's `requirements.txt`:

```
iassis-auth @ git+ssh://git@github.com/Iassis-Medical-Group/iassis-auth.git@v0.2.0
```
or, if `git` cli is not available
```
iassis-auth @ git+https://github.com/Iassis-Medical-Group/iassis-auth.git@v0.2.0
```

Install with the shared constraints file so every service uses the same versions of FastAPI / httpx / PyJWT / pydantic:

```bash
pip install -r requirements.txt \
    -c https://raw.githubusercontent.com/Iassis-Medical-Group/iassis-auth/v0.2.0/constraints.txt
```

To bump a shared dependency org-wide: edit `constraints.txt` in this repo, tag a new release, and update the `@v0.x.y` pin in each consumer.

### 2. Local development — editable install

When iterating on `iassis-auth` itself while a consumer service is running:

```bash
# from the consumer project's venv
pip install -e /absolute/path/to/iassis-auth
```

Edits to `iassis-auth/src/auth/` are picked up on the next import (no reinstall). Pair with `uvicorn --reload` in the consumer for a live loop.

### 3. Vendored wheel — no network / no SSH key at install time

Useful for Docker builds where the base image lacks `git` or SSH agent forwarding (the slim Python images do).

Build the wheel once:

```bash
# from iassis-auth/
python -m pip install build
python -m build --wheel        # → dist/iassis_auth-0.2.0-py3-none-any.whl
```

Copy the wheel into the consumer project (e.g. `consumer/vendor/`) and reference it in `requirements.txt`:

```
./vendor/iassis_auth-0.2.0-py3-none-any.whl
```

In the consumer's `Dockerfile`, copy the vendor dir **before** the `pip install` step so the wheel is available at install time:

```dockerfile
COPY requirements.txt .
COPY ./vendor ./vendor
RUN pip install --no-cache-dir -r requirements.txt
```

Rebuild and re-vendor the wheel whenever `iassis-auth` changes.

> **Docker + git+ssh alternative.** If you want to keep the git URL inside a Docker build instead of vendoring, you need (a) `git` and `openssh-client` installed in the image and (b) BuildKit SSH agent forwarding (`# syntax=docker/dockerfile:1.4`, `RUN --mount=type=ssh pip install ...`, and `docker build --ssh default ...`). The vendored wheel path above sidesteps both.

---

## Configuration

All settings are read from environment variables (or a `.env` file) prefixed with `AUTH_`:

| Variable | Type | Default | Notes |
| --- | --- | --- | --- |
| `AUTH_KEYCLOAK_URL` | string | **required** | e.g. `https://idp.img.com.gr`, no trailing slash. |
| `AUTH_KEYCLOAK_REALM` | string | `master` | Use a **dedicated realm** in any real deployment — `master` is fine for a quick local test only. |
| `AUTH_KEYCLOAK_CLIENT_ID` | string | **required** | This app's Keycloak client id. |
| `AUTH_KEYCLOAK_CLIENT_SECRET` | secret string | **required** | From the client's Credentials tab (confidential client). |
| `AUTH_KEYCLOAK_SCOPE` | string | `openid profile email` | |
| `AUTH_APP_BASE_URL` | string | **required** | This app's own public URL, no trailing slash. Used to derive the Keycloak callback URL (`{prefix}/callback`) — register that exact URL as a Valid Redirect URI in Keycloak. |
| `AUTH_POST_LOGIN_REDIRECT_PATH` | string | `/` | Where the browser lands after a successful login. |
| `AUTH_POST_LOGOUT_REDIRECT_PATH` | string | `/` | Where the browser lands after Keycloak's logout redirect. |
| `AUTH_SESSION_SECRET_KEY` | secret string | **required** | Signs the session cookie. Use ≥ 32 random bytes. |
| `AUTH_SESSION_COOKIE_NAME` | string | `session` | |
| `AUTH_SESSION_MAX_AGE_SECONDS` | int or unset | Starlette default (14 days) | |
| `AUTH_SESSION_HTTPS_ONLY` | bool | `true` | Set `false` only for local HTTP dev. |
| `AUTH_ROLES_SOURCE` | `realm` / `resource` / `both` | `both` | Which claim location `require_roles(...)` reads. |

Generate strong secrets:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

### Keycloak-side setup this depends on

- **Redirect URI**: the client's Valid Redirect URIs must include exactly
  `{AUTH_APP_BASE_URL}{prefix}/callback` (default prefix `/api/auth`).
- **Roles in claims**: `require_roles([...])` reads
  `realm_access.roles` / `resource_access[client_id].roles`, unioned
  across three sources during `/callback`: the verified id_token, the
  userinfo response, and the **unverified access token** (same TLS
  response as the already-verified id_token). Keycloak's stock "roles"
  client scope adds roles to the access token only, so a fully default
  client works with no mapper change. `roles` still comes back empty if
  the "roles" scope isn't assigned to the client at all, or every one of
  its mappers' "Add to ..." toggles is off — check this first if logins
  succeed but every protected route 403s.
- **Realm**: don't run real app clients against `master` — create a
  dedicated realm for this org's applications.

---

## Quick start

```python
# main.py
from fastapi import Depends, FastAPI

from auth import AuthSettings, configure_session, create_auth_router, make_require_roles

app = FastAPI()

# 1. Load AUTH_* env vars
settings = AuthSettings()

# 2. Attach the session middleware — must happen before include_router()
configure_session(app, settings)

# 3. Build the role-checking dependency factory
require_roles = make_require_roles(settings)

# 4. Mount the auth router
app.include_router(create_auth_router(settings=settings))

# 5. Protect your own routes
@app.get("/admin/stats")
def stats(user: dict = Depends(require_roles(["admin"]))):
    return {"by": user["sub"]}

@app.get("/me")
def me(user: dict = Depends(require_roles.get_current_claims)):
    return user
```

This gives you four endpoints out of the box, all `GET` (this is a
browser-redirect flow, not a JSON API):

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/auth/login` | Redirect the browser to Keycloak. Supports `?prompt=none` for a silent SSO probe. |
| GET | `/api/auth/callback` | Keycloak's redirect target — exchanges the code, populates the session, redirects home. |
| GET | `/api/auth/logout` | Clear the session and end Keycloak's SSO session (RP-initiated logout). |
| GET | `/api/auth/me` | `{"authenticated": bool, "user"?: {...}}` for the current session. |

Override the prefix: `create_auth_router(..., prefix="/v2/auth")` — the callback URL registered in Keycloak must match whatever prefix you choose.

---

## Recommended wiring: a consumer-side `app_auth/` package

Splatting the Quick-start snippet into `main.py` works for a single-file app. For anything real, **put the wiring in its own module** (e.g. `your_project/app_auth/__init__.py`) and import the resulting objects from there. This buys one place to load settings and one shared `require_roles` per process that every protected route reaches through the same import path.

### Why not just call it `auth/`?

The library is published as the top-level package **`auth`**. If your project also has a directory named `api/src/auth/`, Python's import system will resolve `from auth import ...` to your local dir before the installed library — silent shadowing that breaks the library import. Name your local wiring module anything else; `app_auth/` is the convention used across IASSIS services.

### The wiring module

```python
# your_project/app_auth/__init__.py
"""Local wiring of the shared `iassis-auth` library for this service."""

from auth import AuthSettings, configure_session, create_auth_router, make_require_roles

from db.db import auth_db  # your project's MongoClient / collection accessor


# 1. Load AUTH_* env vars once per process.
settings = AuthSettings()

# 2. Build the role-checking factory once. Routes import this symbol.
require_roles = make_require_roles(settings)


# 3. Optional: sync a Keycloak login to your own DB record. Enrichment
#    only — returning None still lets the user log in; it just means the
#    session's `user` dict has no `local` key. Gate access to specific
#    routes with `require_roles([...])`, not by rejecting login here.
def _get_or_create_user(claims: dict) -> dict | None:
    return auth_db["personnel"].find_one({"keycloak_sub": claims["sub"]})


# 4. Build the router. Pick a prefix that matches your existing frontend
#    expectations (default `/api/auth`).
router = create_auth_router(
    settings=settings,
    get_or_create_user_fn=_get_or_create_user,
    prefix="/api/auth",
)

__all__ = ["router", "require_roles", "settings"]
```

`configure_session(app, settings)` is **not** called here — it attaches
middleware, which must run against the actual `FastAPI()` instance in
`main.py`, before any router (including this one) is mounted.

### What each export is for

| Export          | Used by                                                                 |
| --------------- | ------------------------------------------------------------------------ |
| `router`        | `app.py` does `app.include_router(router)` once at startup.             |
| `require_roles` | Every protected route: `Depends(require_roles(["admin"]))`.             |
| `settings`      | `app.py` needs it for `configure_session(app, settings)`.                |

### How the rest of the app uses it

```python
# app.py
from fastapi import FastAPI
from auth import configure_session
from app_auth import router as auth_router, settings

app = FastAPI()
configure_session(app, settings)
app.include_router(auth_router)
# ... include your other routers ...
```

```python
# routes/customers.py
from fastapi import APIRouter, Depends
from app_auth import require_roles

router = APIRouter(prefix="/api/customers")

@router.get("")
def list_customers(user: dict = Depends(require_roles(["admin", "agent"]))):
    ...
```

### Things to check in your wiring

- **One `AuthSettings()` call per process.** Importing `app_auth` triggers env-var parsing; missing `AUTH_KEYCLOAK_URL` or `AUTH_SESSION_SECRET_KEY` fails at import time, which is what you want (loud at boot, not on first login).
- **`configure_session` must run in `main.py`, before any router.** Attaching it inside `app_auth/__init__.py` wouldn't have an `app` to attach to yet — pass `settings` back out and call it from `main.py` instead.
- **`get_or_create_user_fn` is optional and enrichment-only.** Use it if a route needs your own business record for the logged-in user; skip it if Keycloak claims + roles are enough on their own.
- **`prefix=` must agree with the frontend/Keycloak client.** The library default is `/api/auth`. Whatever you pick, register `{AUTH_APP_BASE_URL}{prefix}/callback` as a Valid Redirect URI on the Keycloak client.
- **Don't re-export `auth` itself.** Always do `from app_auth import require_roles`, never `from auth import ...` in route files — that keeps the wiring single-sourced and stops the package-name collision from biting you later.

---

## Migration notes (from the old password/JWT version)

This is a breaking rewrite — v0.1.x's username/password login is gone
entirely, replaced by Keycloak. For a full step-by-step walkthrough of
migrating an existing consumer app, see
[`docs/migrating-0.1-to-0.2.md`](docs/migrating-0.1-to-0.2.md). Summary of
what changed:

- **`POST /login` (JSON body) → `GET /login` (browser redirect).** The SPA
  can no longer `fetch()` a login; it must navigate the browser
  (`window.location.href = "/api/auth/login"` or a plain `<a href>`) so
  Keycloak's own login page can render.
- **No access token is ever returned to the client.** Previously,
  `POST /login` handed back `{"token": "..."}` for the SPA to hold in
  memory and send as `Authorization: Bearer`. Now, protected routes rely
  entirely on the session cookie — there is nothing for the SPA to attach
  to outgoing requests beyond `credentials: "include"`.
- **`create_auth_router` dropped `hasher` and `get_user_fn`.** The new
  optional parameter is `get_or_create_user_fn(claims: dict) -> dict | None`
  — same "consumer supplies the DB adapter" shape, different input (Keycloak
  claims instead of a username) and different semantics (enrichment, not a
  login gate).
- **`make_require_roles` reads the session, not a Bearer JWT.** The call
  shape (`require_roles(["admin"])`, `require_roles.get_current_claims`)
  is unchanged, so most consumer route code needs no edits beyond how
  `settings`/`router` get built.
- **All password-era exports are gone**: `PasswordHasher`,
  `make_password_hasher`, `create_access_token`, `create_refresh_token`,
  `decode_token`, `InLogin`, `TokenResponse`, `UserRecord`. There is no
  drop-in replacement for password hashing — Keycloak owns credentials now.

---

## The session `user` shape

After a successful login, `request.session["user"]` (and `GET /me`'s
`user` field) looks like:

```python
{
    "sub": "f3b2...",                    # Keycloak's stable subject id
    "preferred_username": "alice",
    "email": "alice@example.com",
    "name": "Alice Papadopoulou",
    "roles": ["admin"],                  # from extract_roles(), per AUTH_ROLES_SOURCE
    "local": {...},                      # only present if get_or_create_user_fn returned non-None
}
```

---

## Security model

- **Login/session, not password storage.** Keycloak verifies credentials; this library never sees a password.
- **Session cookie**: itsdangerous-signed via Starlette's `SessionMiddleware`, `HttpOnly` by default, `SameSite=Lax` (hardcoded — Keycloak's redirect back is a top-level cross-site navigation, `Strict` would silently break login), `Secure` per `AUTH_SESSION_HTTPS_ONLY`.
- **CSRF on login**: `state` is generated per `/login` call, stashed in the session, and checked on `/callback` before any token exchange happens.
- **RP-initiated logout**: `/logout` clears the local session and redirects through Keycloak's `end_session_endpoint` with `id_token_hint`, ending the realm-wide SSO session too — not just this app's.
- **Tokens never reach the browser.** Keycloak's `access_token`/`refresh_token` are used only server-side during `/callback` (the userinfo call, plus an unverified decode of the access token to read role claims) and then discarded, not persisted — mirroring `keycloak-sample-client`'s reasoning: nothing calls a protected API with them today, and keeping more risks exceeding proxy header buffers / the ~4KB per-cookie browser limit. The access token is decoded without signature verification: it rides in the same TLS response as the id_token, whose signature *is* verified, so transport trust is already established.
- **Revocation**: none of this is revocable mid-session beyond clearing the local cookie — Keycloak's own SSO session ends via `/logout`, but a session that was never explicitly logged out lives until `AUTH_SESSION_MAX_AGE_SECONDS` expires.

### Operational checklist

- [ ] `AUTH_SESSION_SECRET_KEY` set per environment, never committed.
- [ ] Different secrets in dev / staging / prod.
- [ ] Secrets stored in your secret manager (Vault, AWS SM, …), not in `.env` files in production.
- [ ] `AUTH_SESSION_HTTPS_ONLY=true` in any environment served over HTTPS.
- [ ] Keycloak client's Valid Redirect URIs exactly match `{AUTH_APP_BASE_URL}{prefix}/callback`.
- [ ] "roles" client scope assigned to the client (stock default), if any route uses `require_roles([...])` with non-empty roles — roles are read from the access token, so no "Add to ID token" mapper change is needed.
- [ ] Running against a dedicated realm, not `master`.

---

## Development

### Set up

```bash
git clone git@github.com:Iassis-Medical-Group/iassis-auth.git
cd iassis-auth
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

### Build a wheel

```bash
python -m build
# → dist/iassis_auth-0.2.0-py3-none-any.whl
```

### Run end-to-end against a real Keycloak instance

Unlike the old password-based version, there's no way to demo this
library with zero external services — it needs a Keycloak realm to
redirect to. The quickest path is a local throwaway instance:

```bash
docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
    quay.io/keycloak/keycloak:latest start-dev
```

Then, in the admin console (`http://localhost:8080`):

1. Create a realm (anything other than `master`).
2. Create a confidential client, e.g. `demo-client`, with Standard Flow
   enabled and a Valid Redirect URI of `http://localhost:8000/api/auth/callback`.
3. Copy its client secret from the Credentials tab.

```bash
export AUTH_KEYCLOAK_URL=http://localhost:8080
export AUTH_KEYCLOAK_REALM=your-realm
export AUTH_KEYCLOAK_CLIENT_ID=demo-client
export AUTH_KEYCLOAK_CLIENT_SECRET=<paste secret>
export AUTH_APP_BASE_URL=http://localhost:8000
export AUTH_SESSION_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(64))")
export AUTH_SESSION_HTTPS_ONLY=false

cat > demo.py <<'PY'
from fastapi import Depends, FastAPI
from auth import AuthSettings, configure_session, create_auth_router, make_require_roles

settings = AuthSettings()
require_roles = make_require_roles(settings)

app = FastAPI()
configure_session(app, settings)
app.include_router(create_auth_router(settings=settings))

@app.get("/whoami")
def whoami(user: dict = Depends(require_roles.get_current_claims)):
    return user
PY

uvicorn demo:app --reload --port 8000
```

Open `http://localhost:8000/api/auth/login` in a browser, log in, and
you'll be redirected back with a session cookie set; `/api/auth/me` and
`/whoami` will both show the authenticated user.

### Run the test suite

```bash
pytest -q                    # all tests
pytest -q -k callback        # filter
pytest -q --cov=auth         # with coverage (needs pytest-cov)
```

---

## Releasing

1. Bump `version` in `pyproject.toml`.
2. Update `constraints.txt` if shared dependency versions changed.
3. Commit, push, and tag:
   ```bash
   git tag v0.2.0
   git push --tags
   ```
4. CI builds the wheel and attaches it to the GitHub release.
5. Bump the `@v0.x.y` pin in each consumer project.

---

## What's next

This library is deliberately scoped to **one app's** login/logout/session
— it does not yet address the org's longer-term goal of logging into one
app (e.g. an influencer tool) and staying authenticated across other
platforms (methub, methub API, CRM), or letting one app's SPA call
another app's backend directly. That design — RFC 8693 Token Exchange,
one Keycloak client per app, and stateless Bearer-JWT verification on
each resource server — is written up in `plan-keycloak.md` in this repo.
None of it is implemented here yet; this single-app BFF pattern is step
one toward it.

---

## Public API

```python
from auth import (
    AuthSettings,          # pydantic-settings model, reads AUTH_* env vars
    ErrorResponse,         # error envelope model (401/403 response docs)

    configure_session,     # (app, settings) -> None — attach the session middleware
    create_auth_router,    # (*, settings, prefix="/api/auth", get_or_create_user_fn=None) -> APIRouter
    make_require_roles,    # (settings) -> require_roles(roles) dependency factory
)
```

Lower-level OIDC primitives (`discover`, `build_authorize_url`,
`exchange_code_for_tokens`, `verify_id_token`, `read_access_token_claims`,
`extract_roles`, ...) live in `auth.keycloak` for advanced consumers, but
aren't part of the top-level public API.