# iassis-auth

Shared FastAPI authentication library for IASSIS Medical Group internal services.

Provides JWT access/refresh tokens, argon2id password hashing with a deployment-wide pepper, and role-based route protection — wired into any FastAPI app via a single `create_auth_router(...)` call. The library performs **no database I/O** itself; each consuming project supplies a `get_user_fn` callback so the same library works against personnel, influencer, or any other user collection.

---

## Features

- **Argon2id password hashing** via `pwdlib`, with per-password random salt.
- **Deployment pepper** mixed in via HMAC-SHA256 pre-hash — pepper never reaches the database.
- **JWT access + refresh tokens** (`HS256` by default), refresh token stored as `HttpOnly` cookie.
- **Role-based dependencies** (`require_roles(["admin"])`) for protecting endpoints.
- **Schema-agnostic**: consumer supplies a `get_user_fn` adapter, so nested (`auth.username`) or flat user documents are both supported.
- **Constant-time decoy** on missing-user login path to prevent username enumeration via timing.
- **Pure functions for tokens**; factory-built dependencies and hashers — no hidden module-level globals or state.

---

## Installation

Three install paths depending on where you are in the release cycle.

### 1. Production / shared services — tagged release (preferred)

Once a `vX.Y.Z` tag exists on the internal GitHub repo, pin it in your consumer's `requirements.txt`:

```
iassis-auth @ git+ssh://git@github.com/Iassis-Medical-Group/iassis-auth.git@v0.1.0
```
or, if `git` cli is not available
```
iassis-auth @ git+https://github.com/Iassis-Medical-Group/iassis-auth.git@v0.1.0
```

Install with the shared constraints file so every service uses the same versions of FastAPI / pwdlib / PyJWT / pydantic:

```bash
pip install -r requirements.txt \
    -c https://raw.githubusercontent.com/Iassis-Medical-Group/iassis-auth/v0.1.0/constraints.txt
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
python -m build --wheel        # → dist/iassis_auth-0.1.0-py3-none-any.whl
```

Copy the wheel into the consumer project (e.g. `consumer/vendor/`) and reference it in `requirements.txt`:

```
./vendor/iassis_auth-0.1.0-py3-none-any.whl
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

| Variable                   | Type                       | Default               | Notes                                                       |
| -------------------------- | -------------------------- | --------------------- | ----------------------------------------------------------- |
| `AUTH_JWT_SECRET_KEY`      | secret string              | **required**          | Signs JWTs. Use ≥ 32 random bytes.                          |
| `AUTH_PEPPER_SECRET`       | secret string              | **required**          | HMAC key mixed into every password hash. Never reaches DB.  |
| `AUTH_JWT_ALGORITHM`       | string                     | `HS256`               |                                                             |
| `AUTH_ACCESS_TTL_MINUTES`  | int                        | `480`                 | Access token lifetime.                                      |
| `AUTH_REFRESH_TTL_MINUTES` | int                        | `1440`                | Refresh token lifetime.                                     |
| `AUTH_REFRESH_COOKIE_PATH` | string                     | `/api/auth/refresh`   | Cookie scope path.                                          |
| `AUTH_SECURE_COOKIE`       | bool                       | `true`                | Set `false` only for local HTTP dev.                        |
| `AUTH_COOKIE_SAMESITE`     | `strict` / `lax` / `none`  | `strict`              |                                                             |

Generate strong secrets:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

### Argon2id parameters (optional)

By default the hasher uses sane argon2id parameters (t=3, m=64 MiB, p=4, hash_len=32, salt_len=16). Override by passing a YAML config path:

```yaml
# hasher-config.yaml
time_cost: 3
memory_cost: 65536
parallelism: 4
hash_len: 32
salt_len: 16
```

```python
hasher = make_password_hasher(settings, hasher_config_path="./hasher-config.yaml")
```

Tune `memory_cost` / `time_cost` to target ~100 ms per hash on production hardware.

---

## Quick start

```python
# main.py
from fastapi import Depends, FastAPI
from pymongo import MongoClient

from auth import (
    AuthSettings,
    UserRecord,
    create_auth_router,
    make_password_hasher,
    make_require_roles,
)

app = FastAPI()

# 1. Load AUTH_* env vars
settings = AuthSettings()

# 2. Build the password hasher (pepper bound here)
hasher = make_password_hasher(settings)

# 3. Build the role-checking dependency factory
require_roles = make_require_roles(settings)

# 4. Adapter: read your DB, return the normalized UserRecord shape
personnel = MongoClient("mongodb://localhost:27017")["mydb"]["personnel"]

def get_user(username: str) -> UserRecord | None:
    doc = personnel.find_one({"auth.username": username})
    if not doc:
        return None
    a = doc["auth"]
    return UserRecord(
        identity=a["username"],
        password_hash=a["password_hash"],
        roles=a.get("roles", []),
        is_active=a.get("is_active", True),
    )

# 5. Mount the auth router
app.include_router(create_auth_router(
    settings=settings,
    hasher=hasher,
    get_user_fn=get_user,
))

# 6. Protect your own routes
@app.get("/admin/stats")
def stats(claims: dict = Depends(require_roles(["admin"]))):
    return {"by": claims["sub"]}

@app.get("/me")
def me(claims: dict = Depends(require_roles.get_current_claims)):
    return claims
```

This gives you three endpoints out of the box:

| Method | Path                  | Purpose                                              |
| ------ | --------------------- | ---------------------------------------------------- |
| POST   | `/api/auth/login`     | Verify credentials, set refresh cookie, return token |
| POST   | `/api/auth/refresh`   | Mint a fresh access token from the refresh cookie    |
| POST   | `/api/auth/logout`    | Clear the refresh cookie                             |

Override the prefix: `create_auth_router(..., prefix="/v2/auth")`.

---

## Recommended wiring: a consumer-side `app_auth/` package

Splatting the Quick-start snippet into `main.py` works for a single-file app. For anything real, **put the wiring in its own module** (e.g. `your_project/app_auth/__init__.py`) and import the resulting objects from there. This buys three things: one place to load settings, one shared `hasher`/`require_roles` per process, and one `get_user_fn` definition that every protected route reaches through the same import path.

### Why not just call it `auth/`?

The library is published as the top-level package **`auth`**. If your project also has a directory named `api/src/auth/`, Python's import system will resolve `from auth import ...` to your local dir before the installed library — silent shadowing that breaks the library import. Name your local wiring module anything else; `app_auth/` is the convention used by the IASSIS competitor-analysis service.

### The wiring module

```python
# your_project/app_auth/__init__.py
"""Local wiring of the shared `iassis-auth` library against this service's user collection."""

from auth import (
    AuthSettings,
    UserRecord,
    create_auth_router,
    make_password_hasher,
    make_require_roles,
)

from db.db import auth_db  # your project's MongoClient / collection accessor


# 1. Load AUTH_* env vars once per process.
settings = AuthSettings()

# 2. Build the hasher once (pepper-bound; pwdlib instance is reused).
hasher = make_password_hasher(settings)

# 3. Build the role-checking factory once. Routes import this symbol.
require_roles = make_require_roles(settings)


# 4. Adapter: read your DB, return the normalised UserRecord shape.
def _get_user(username: str) -> UserRecord | None:
    doc = auth_db["personnel"].find_one({"auth.username": username})
    if not doc:
        return None
    a = doc.get("auth", {})
    return UserRecord(
        identity=a.get("username", username),
        password_hash=a.get("password_hash", ""),
        roles=a.get("roles", []),
        is_active=a.get("is_active", True),
    )


# 5. Build the router. Pick a prefix that matches your existing frontend
#    expectations (default `/api/auth`, here `/api/jwt` to preserve the
#    pre-existing client). Cookie path is set via AUTH_REFRESH_COOKIE_PATH.
router = create_auth_router(
    settings=settings,
    hasher=hasher,
    get_user_fn=_get_user,
    prefix="/api/jwt",
)

__all__ = ["router", "require_roles", "hasher", "settings"]
```

### What each export is for

| Export          | Used by                                                                 |
| --------------- | ----------------------------------------------------------------------- |
| `router`        | `app.py` does `app.include_router(router)` once at startup.             |
| `require_roles` | Every protected route: `Depends(require_roles(["admin"]))`.             |
| `hasher`        | Seed / registration / password-reset scripts that need `hasher.hash()`. |
| `settings`      | Rare — only if you need to read TTLs or cookie config elsewhere.        |

### How the rest of the app uses it

```python
# app.py
from fastapi import FastAPI
from app_auth import router as auth_router

app = FastAPI()
app.include_router(auth_router)
# ... include your other routers ...
```

```python
# routes/customers.py
from fastapi import APIRouter, Depends
from app_auth import require_roles

router = APIRouter(prefix="/api/customers")

@router.get("")
def list_customers(claims: dict = Depends(require_roles(["admin", "agent"]))):
    ...
```

### Things to check in your wiring

- **One `AuthSettings()` call per process.** Importing `app_auth` triggers env-var parsing; missing `AUTH_JWT_SECRET_KEY` or `AUTH_PEPPER_SECRET` fails at import time, which is what you want (loud at boot, not on first login).
- **One `make_password_hasher(settings)` call per process.** It pre-bakes a dummy hash for the constant-time decoy; rebuilding it per request wastes ~100 ms each time.
- **`get_user_fn` is the only piece that knows your schema.** Nested `auth.username`, flat `email`, an influencer table — they all collapse into the same `UserRecord` shape here. If you need to change which collection or field stores users, this function is the single edit.
- **`prefix=` must agree with the frontend.** The library default is `/api/auth`. Override it to keep an existing client working (`/api/jwt` in this example). Set `AUTH_REFRESH_COOKIE_PATH` to `<prefix>/refresh` so the cookie scope matches the route.
- **Don't re-export `auth` itself.** Always do `from app_auth import require_roles`, never `from auth import ...` in route files — that keeps the wiring single-sourced and stops the package-name collision from biting you later.

---

## Hashing a password (registration / seed scripts)

```python
from auth import AuthSettings, make_password_hasher

settings = AuthSettings()
hasher = make_password_hasher(settings)

stored = hasher.hash("hunter2-correct-horse")
# Persist `stored` in your user document, e.g. auth.password_hash = stored
```

The same `AUTH_PEPPER_SECRET` must be set in every environment that hashes or verifies passwords. Rotating the pepper invalidates all existing stored hashes.

---

## The `UserRecord` shape

Your `get_user_fn` must return either `None` or a `UserRecord`:

```python
class UserRecord(BaseModel):
    identity: str            # goes into JWT `sub`
    password_hash: str       # argon2id PHC string from a previous hasher.hash() call
    roles: list[str] = []    # used by require_roles(...)
    is_active: bool = True   # False → 403 at login
    extra_claims: dict = {}  # optional, merged into JWT (e.g. {"account_type": "influencer"})
```

Adapt nested documents (e.g. `personnel.auth.username`) or flat ones (e.g. an influencer collection) the same way — the library only sees the normalized record.

---

## Security model

- **Password storage**: `argon2id(HMAC-SHA256(pepper, password), salt, t, m, p)`. Salt is per-password and stored inside the PHC string. Pepper is environment-only.
- **Pepper applied as HMAC**: protects against password shucking when paired with secret pepper management.
- **JWT signing**: HMAC (default `HS256`) over `AUTH_JWT_SECRET_KEY`.
- **Refresh token**: `HttpOnly` cookie scoped to `refresh_cookie_path`; `Secure` + `SameSite=Strict` by default.
- **Username enumeration**: missing-user login path runs `hasher.dummy_verify()` so wrong-username and wrong-password paths take equivalent wall-clock time.
- **Disabled accounts**: `is_active=False` returns 403 at login, and `/refresh` also re-checks `is_active` so a disabled user cannot keep refreshing.

### Operational checklist

- [ ] `AUTH_JWT_SECRET_KEY` and `AUTH_PEPPER_SECRET` set per environment, never committed.
- [ ] Different secrets in dev / staging / prod.
- [ ] Secrets stored in your secret manager (Vault, AWS SM, …), not in `.env` files in production.
- [ ] `AUTH_SECURE_COOKIE=true` in any environment served over HTTPS.
- [ ] Argon2id parameters tuned to ~100 ms per hash on your prod host.

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
# → dist/iassis_auth-0.1.0-py3-none-any.whl
```

### Run end-to-end against a throwaway FastAPI app

Stand the library up in isolation — no database, in-memory users, single uvicorn process. Useful for verifying changes before touching a consumer service.

```bash
# 1. Activate the dev venv (see "Set up" above).
# 2. Export the two required secrets:
export AUTH_JWT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(64))")
export AUTH_PEPPER_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(64))")
export AUTH_SECURE_COOKIE=false        # local HTTP

# 3. Save as demo.py:
cat > demo.py <<'PY'
from fastapi import Depends, FastAPI
from auth import (
    AuthSettings, UserRecord,
    create_auth_router, make_password_hasher, make_require_roles,
)

settings = AuthSettings()
hasher = make_password_hasher(settings)
require_roles = make_require_roles(settings)

# Pre-hash one in-memory user.
USERS = {
    "alice": UserRecord(
        identity="alice",
        password_hash=hasher.hash("hunter2"),
        roles=["admin"],
    ),
}

app = FastAPI()
app.include_router(create_auth_router(
    settings=settings,
    hasher=hasher,
    get_user_fn=lambda u: USERS.get(u),
))

@app.get("/whoami")
def whoami(claims: dict = Depends(require_roles(["admin"]))):
    return claims
PY

# 4. Run:
uvicorn demo:app --reload --port 8000
```

Smoke-test from another terminal:

```bash
# Login (sets HttpOnly refresh cookie, returns access token in body)
TOKEN=$(curl -s -c cookies.txt -X POST localhost:8000/api/auth/login \
        -H 'content-type: application/json' \
        -d '{"username":"alice","password":"hunter2"}' | jq -r .token)

# Hit a protected endpoint
curl -s localhost:8000/whoami -H "Authorization: Bearer $TOKEN"

# Refresh from the cookie
curl -s -b cookies.txt -X POST localhost:8000/api/auth/refresh

# Logout (clears cookie)
curl -s -b cookies.txt -c cookies.txt -X POST localhost:8000/api/auth/logout
```

### Run in Docker

There is no Dockerfile in this repo — the library has no runtime of its own. Docker comes in only when a **consumer service** installs it. Two patterns:

**Vendored wheel (recommended for slim base images).** See [Installation §3](#3-vendored-wheel--no-network--no-ssh-key-at-install-time). The consumer copies the wheel into its build context and `pip install`s from a local path — no `git`, no SSH key, fast.

**git+ssh with BuildKit.** If a consumer prefers pinning by tag without vendoring, its Dockerfile needs `git` + `openssh-client` and BuildKit SSH forwarding:

```dockerfile
# syntax=docker/dockerfile:1.4
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        git openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p -m 0700 ~/.ssh \
    && ssh-keyscan github.com >> ~/.ssh/known_hosts
COPY requirements.txt .
RUN --mount=type=ssh pip install --no-cache-dir -r requirements.txt
```

Build with the host's SSH agent forwarded:

```bash
docker build --ssh default -t my-consumer .
# or, with compose:
DOCKER_BUILDKIT=1 docker compose build --ssh default
```

### Run the test suite

```bash
pytest -q                    # all tests
pytest -q -k login           # filter
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

## Public API

```python
from auth import (
    AuthSettings,            # pydantic-settings model, reads AUTH_* env vars
    UserRecord,              # normalized shape get_user_fn must return
    InLogin, TokenResponse,  # request / response Pydantic models
    PasswordHasher,          # struct holding hash / verify / dummy_verify

    make_password_hasher,    # (settings, hasher_config_path=None) -> PasswordHasher
    make_require_roles,      # (settings) -> require_roles(roles) dependency factory
    create_auth_router,      # (*, settings, hasher, get_user_fn, prefix=...) -> APIRouter

    create_access_token,     # (settings, identity, roles, extra=None) -> str
    create_refresh_token,    # (settings, identity, roles) -> str
    decode_token,            # (settings, token) -> dict
)
```
