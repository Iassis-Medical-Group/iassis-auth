from pydantic import BaseModel, Field


class InLogin(BaseModel):
    """Request body for `POST /login`."""

    username: str = Field(
        ...,
        description="User identifier as stored in the consumer's user collection.",
        examples=["alice"],
        min_length=1,
    )
    password: str = Field(
        ...,
        description="Plaintext password. Verified against the argon2id+pepper hash stored on the user record.",
        examples=["correct horse battery staple"],
        min_length=1,
    )


class TokenResponse(BaseModel):
    """Response body for `POST /login` and `POST /refresh`."""

    token: str = Field(
        ...,
        description=(
            "JWT access token. HS256-signed by default; payload contains "
            "`sub` (identity), `roles`, `type=access`, `exp`, plus any "
            "`extra_claims` returned by the consumer's `get_user_fn`. "
            "Lifetime controlled by `AUTH_ACCESS_TTL_MINUTES`."
        ),
        examples=["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."],
    )


class ErrorResponse(BaseModel):
    """Standard error envelope (matches FastAPI's default HTTPException shape)."""

    detail: str = Field(..., examples=["Unauthorized"])


class UserRecord(BaseModel):
    """Normalized user shape that a consumer's `get_user_fn` must return.

    The library is blind to the consumer's underlying document schema —
    callers adapt their own document (nested `auth.username` or flat
    fields) into this shape before returning it.
    """

    identity: str = Field(
        ...,
        description="Stable identifier placed in the JWT `sub` claim. Typically a username or user id.",
        examples=["alice"],
    )
    password_hash: str = Field(
        ...,
        description="Argon2id PHC string previously produced by `PasswordHasher.hash()`.",
        examples=["$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>"],
    )
    roles: list[str] = Field(
        default_factory=list,
        description="Roles granted to this user; checked by `require_roles(...)` dependencies.",
        examples=[["admin", "staff"]],
    )
    is_active: bool = Field(
        default=True,
        description="If False, login returns 401.",
    )
    extra_claims: dict = Field(
        default_factory=dict,
        description="Optional extra JWT payload merged into access tokens (e.g. `account_type`, `uid`).",
        examples=[{"account_type": "influencer", "uid": "infl_42"}],
    )