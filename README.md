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

Distributed via tagged releases on the internal GitHub repository. Add to your project's `requirements.txt`:

```
iassis-auth @ git+ssh://git@github.com/<org>/iassis-auth.git@v0.1.0
```

Install with the shared constraints file so every service uses the same versions of FastAPI / pwdlib / PyJWT / pydantic:

```bash
pip install -r requirements.txt \
    -c https://raw.githubusercontent.com/<org>/iassis-auth/v0.1.0/constraints.txt
```

To bump a shared dependency org-wide: edit `constraints.txt` in this repo, tag a new release, and update the `@v0.x.y` pin in each consumer.

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

```bash
git clone git@github.com:<org>/iassis-auth.git
cd iassis-auth
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

Build a wheel for local testing:

```bash
python -m build
pip install dist/iassis_auth-0.1.0-py3-none-any.whl
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
