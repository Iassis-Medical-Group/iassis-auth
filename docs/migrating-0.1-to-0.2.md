# Migrating a consumer app from `iassis-auth` v0.1.x to v0.2.0

`iassis-auth` v0.2.0 is a breaking rewrite: the custom username/password +
self-issued JWT flow (v0.1.x) is gone, replaced by Keycloak login/logout
with a Starlette signed-cookie session. This doc walks through migrating
one consumer app (e.g. `img-erp-services`, `img-influencers-tool`,
`medit-mylaser-competitor-analysis`) end to end.

Do this migration **per app, on its own branch**, one app at a time. There
is no shared cutover — v0.1.0 and v0.2.0 consumers can coexist indefinitely
since each app pins its own tag.

See the main [README](../README.md) for what each new function does; this
doc is only about the *migration path* from the old shape to the new one.

---

## Prerequisites

A Keycloak client must exist for the app being migrated (confidential,
Standard Flow enabled) in a dedicated realm — not `master`. Its Valid
Redirect URIs need to include `{app base URL}{auth prefix}/callback` for
every environment the app runs in (local, staging, prod), e.g.
`http://localhost:8000/api/auth/callback` and
`https://yourapp.img.com.gr/api/auth/callback`.

The client's "roles" client scope needs to be a **Default** scope, with
"Add to ID token" enabled on its realm-roles and client-roles mappers —
otherwise every `require_roles([...])` check denies everyone once you cut
over (see the README's "Keycloak-side setup" section for why).

Before touching code, decide which of the app's existing users need
mapping to a Keycloak identity — that decision drives whether the app
needs a `get_or_create_user_fn` at all (see the "existing local users"
section below).

---

## 1. Bump the pin

```diff
- iassis-auth @ git+https://github.com/Iassis-Medical-Group/iassis-auth.git@v0.1.0
+ iassis-auth @ git+https://github.com/Iassis-Medical-Group/iassis-auth.git@v0.2.0
```

Re-install against the matching constraints file:

```bash
pip install -r requirements.txt \
    -c https://raw.githubusercontent.com/Iassis-Medical-Group/iassis-auth/v0.2.0/constraints.txt
```

If the app vendors a wheel instead (Docker builds without SSH), rebuild it
from the `v0.2.0` tag and re-copy it into `vendor/` — see the README's
"Vendored wheel" install path.

---

## 2. Update environment variables

Drop the old `AUTH_JWT_*` / `AUTH_PEPPER_SECRET` / `AUTH_REFRESH_*` /
`AUTH_COOKIE_SAMESITE` vars. Add the new ones:

```diff
- AUTH_JWT_SECRET_KEY=...
- AUTH_PEPPER_SECRET=...
- AUTH_JWT_ALGORITHM=HS256
- AUTH_ACCESS_TTL_MINUTES=480
- AUTH_REFRESH_TTL_MINUTES=1440
- AUTH_REFRESH_COOKIE_PATH=/api/auth/refresh
- AUTH_SECURE_COOKIE=true
- AUTH_COOKIE_SAMESITE=strict
+ AUTH_KEYCLOAK_URL=https://idp.img.com.gr
+ AUTH_KEYCLOAK_REALM=<the app's dedicated realm>
+ AUTH_KEYCLOAK_CLIENT_ID=<this app's client id>
+ AUTH_KEYCLOAK_CLIENT_SECRET=<from the client's Credentials tab>
+ AUTH_APP_BASE_URL=https://yourapp.img.com.gr
+ AUTH_SESSION_SECRET_KEY=<generate: python -c "import secrets; print(secrets.token_urlsafe(64))">
+ AUTH_SESSION_HTTPS_ONLY=true
```

`AUTH_SESSION_HTTPS_ONLY=false` locally over plain HTTP, same role the old
`AUTH_SECURE_COOKIE` played. Full field list and defaults are in the
README's Configuration table.

---

## 3. Rewrite `app_auth/__init__.py`

Every known consumer wires the library through a module like
`your_project/app_auth/__init__.py`. Old shape (`img-erp-services`
pattern):

```python
# BEFORE (v0.1.x)
from auth import AuthSettings, UserRecord, create_auth_router, make_password_hasher, make_require_roles
from database import get_personnel_collection

settings = AuthSettings()
hasher = make_password_hasher(settings)
require_roles = make_require_roles(settings)

def _get_user(username: str) -> UserRecord | None:
    doc = get_personnel_collection().find_one({"auth.username": username})
    if not doc:
        return None
    a = doc["auth"]
    return UserRecord(
        identity=a["username"],
        password_hash=a["password_hash"],
        roles=a.get("roles", []),
        is_active=a.get("is_active", True),
    )

router = create_auth_router(settings=settings, hasher=hasher, get_user_fn=_get_user)

__all__ = ["router", "require_roles", "hasher", "settings"]
```

New shape:

```python
# AFTER (v0.2.0)
from auth import AuthSettings, create_auth_router, make_require_roles
from database import get_personnel_collection

settings = AuthSettings()
require_roles = make_require_roles(settings)

def _get_or_create_user(claims: dict) -> dict | None:
    """Enrichment only — Keycloak alone decides who can log in.

    Returning None does not block login; it just means the session's
    `user` dict has no `local` key.
    """
    return get_personnel_collection().find_one({"keycloak_sub": claims["sub"]})

router = create_auth_router(settings=settings, get_or_create_user_fn=_get_or_create_user)

__all__ = ["router", "require_roles", "settings"]
```

What changed:

| | v0.1.x | v0.2.0 |
|---|---|---|
| Identity lookup key | `username` string | Keycloak claims dict (`claims["sub"]`, `claims["email"]`, ...) |
| `hasher` | required, exported | gone entirely |
| Router param | `get_user_fn(username) -> UserRecord \| None` | `get_or_create_user_fn(claims) -> dict \| None` |
| `None` return means | "unknown user, 401" | "no local record yet, login still succeeds" |
| Return shape | `UserRecord` pydantic model | any plain dict (or `None`) |
| `settings` export | rarely used | needed — `main.py` uses it for `configure_session` |

The lookup needs a `keycloak_sub` field (or equivalent) on the app's
personnel/user documents. If the DB currently keys users by username only,
back-fill it: the simplest place is inside `_get_or_create_user` itself,
matching on the old key the first time a given user logs in post-migration
(`update_one({"auth.username": claims["preferred_username"]}, {"$set": {"keycloak_sub": claims["sub"]}})`)
rather than writing a separate one-off script.

---

## Existing local users

Three realistic situations, decided per app:

1. **Every existing user already exists in Keycloak** (IT provisioned the
   realm from the app's user list). `_get_or_create_user` just looks them
   up — no new users get created, nothing else to do.
2. **Some existing users aren't in Keycloak yet.** They can't log in until
   someone creates their Keycloak account — that's an IT/admin action, not
   something `iassis-auth` automates. `_get_or_create_user` returning
   `None` for them is correct; whether an unmatched user sees a degraded
   experience or a "contact IT" message is a decision for the app's own
   routes, not this library.
3. **Self-service account linking on first login** — create the local
   record right there in `_get_or_create_user` if it doesn't exist yet.
   That's a legitimate use of "enrichment", but it's provisioning, not a
   security decision: `require_roles([...])` on protected routes is still
   what gates access, not this function.

---

## 4. Update `main.py`

```diff
  from fastapi import FastAPI
- from app_auth import require_roles, router as auth_router
+ from auth import configure_session
+ from app_auth import require_roles, router as auth_router, settings

  app = FastAPI()
+ configure_session(app, settings)
  app.include_router(auth_router)
  # ... other routers ...
```

`configure_session` has to run in `main.py`, against the real `app`
instance, before `include_router(auth_router)` — it can't live inside
`app_auth/__init__.py` since that module doesn't have `app` yet.

If `main.py` already used `SessionMiddleware` or any other session/cookie
middleware for something unrelated to auth, watch for conflicts —
`configure_session` adds its own `SessionMiddleware` instance; don't add a
second one.

---

## 5. Route prefixes and paths

If the app overrode the router prefix (e.g. `/api/jwt` in the
`medit-mylaser-competitor-analysis` pattern), the four routes stay at that
same prefix, just with different paths and verbs:

| v0.1.x | v0.2.0 |
|---|---|
| `POST {prefix}/login` | `GET {prefix}/login` |
| `POST {prefix}/refresh` | gone — no client-visible refresh step; the session cookie keeps working on its own |
| `POST {prefix}/logout` | `GET {prefix}/logout` |
| — | `GET {prefix}/callback` — new, register this exact URL in Keycloak |
| — | `GET {prefix}/me` — new |

Whatever `prefix` is chosen, the Keycloak client's Valid Redirect URI must
match `{AUTH_APP_BASE_URL}{prefix}/callback` exactly.

---

## 6. Frontend changes

This is the part most likely to need real UI work, not just a config
change:

- **Login trigger**: replace any XHR/fetch-based `POST /api/auth/login`
  call with a plain browser navigation —
  `window.location.href = "/api/auth/login"` or
  `<a href="/api/auth/login">Login</a>`.
- **Logout trigger**: same shift, `GET` navigation instead of a `POST`
  fetch.
- **No more access token in JS memory.** Anywhere the SPA currently sends
  `Authorization: Bearer ${token}` on its own API calls, remove it — the
  session cookie (`credentials: "include"` on `fetch`) is what
  authenticates now. If the API previously *required* a bearer header for
  something other than the SPA (a mobile client, a non-browser
  integration), that's outside this migration's scope — resolve it with
  whoever owns that integration before cutting over.
- **"Am I logged in" check**: replace whatever previously inspected the
  in-memory access token (a decoded JWT payload, a "do we have a token
  variable set" flag) with a
  `fetch("/api/auth/me", {credentials: "include"})` call on app load.
  Response shape: `{"authenticated": bool, "user"?: {...}}`.
- **No more manual refresh-token dance.** The old `POST /refresh` call
  (typically on a timer or on 401) has nothing to call anymore. Session
  lifetime is controlled server-side via `AUTH_SESSION_MAX_AGE_SECONDS`.
- Any claim the frontend read out of the old JWT payload (`account_type`,
  `uid`, or other `extra_claims`/`UserRecord` fields) needs a new source:
  either a Keycloak claim (if a mapper puts it there) or `user.local`
  (whatever `_get_or_create_user` returns), both visible via
  `GET /api/auth/me`.

---

## 7. Protected backend routes

`require_roles(...)` and `require_roles.get_current_claims` keep the same
call shape on either version:

```python
# Unchanged
@router.get("")
def list_customers(claims: dict = Depends(require_roles(["admin", "agent"]))):
    ...
```

What changed underneath: `claims` used to be the decoded JWT payload
(`sub`, `roles`, `type`, `exp`, plus whatever `extra_claims` had). It's now
the session `user` dict (`sub`, `preferred_username`, `email`, `name`,
`roles`, optional `local`). Audit any route reading a claim key that only
existed in the old JWT shape (`payload["type"]`, `payload["exp"]`, custom
`extra_claims` keys) — those need to come from `user["local"]` now, via
whatever `_get_or_create_user` attaches.

---

## 8. Verifying the migration

Before considering the cutover done, confirm:

- `GET /api/auth/login` redirects to Keycloak, with `client_id`,
  `redirect_uri`, and `state` present in the URL.
- Logging in with a real Keycloak account lands back on the app with
  `GET /api/auth/me` reporting `authenticated: true`.
- A user with the right role in Keycloak can reach a
  `require_roles(["admin"])` route; a user without it gets 403.
- A Keycloak-authenticated user with no matching local record (per the
  "existing local users" section) behaves the way that section decided —
  not a 500, not an accidental full-access grant.
- `GET /api/auth/logout` clears the session *and* redirects through
  Keycloak. Hitting `/api/auth/login` again immediately after should
  either show a real login page or silently re-authenticate via SSO —
  either is expected; the thing to actually watch for is being logged out
  of only the app but not Keycloak.
- CORS/cookie behavior matches the real deployment shape — a same-origin
  setup via a reverse proxy (as in the `keycloak-sample-client` reference)
  needs no CORS config at all; confirm which shape the app actually uses
  before assuming new CORS config is needed.

---

## Rolling back

Since each app pins its own tag, rolling back one app is independent of
the others: revert the `requirements.txt` pin to `@v0.1.0`, restore the
previous `app_auth/__init__.py` and `main.py`, and restore the old
`AUTH_*` env vars. Nothing in `iassis-auth` itself needs to change.

---

## What this migration does not cover

Cross-app SSO (log into one app, stay authenticated in another) and
letting one app's SPA call another app's backend directly are not part of
this migration — that's the RFC 8693 Token Exchange design in
[`plan-keycloak.md`](../plan-keycloak.md), still unimplemented. This
migration only gets one app onto Keycloak-backed login for itself.