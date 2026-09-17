"""Token related request and response schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.core.rbac import Permission, Role


class TokenPair(BaseModel):
    """Access and refresh tokens returned by login and refresh."""

    model_config = ConfigDict(from_attributes=True)

    access_token: str = Field(description="Short lived bearer token.")
    refresh_token: str = Field(description="Long lived token used to mint access tokens.")
    token_type: str = Field(default="bearer", description="Authorization scheme to use.")
    expires_in: int = Field(description="Access token lifetime in seconds.")
    access_token_expires_at: datetime = Field(description="Absolute access token expiry (UTC).")
    refresh_token_expires_at: datetime = Field(description="Absolute refresh token expiry (UTC).")


class RefreshRequest(BaseModel):
    """Body of the refresh endpoint."""

    refresh_token: str = Field(min_length=1, description="A valid, unrevoked refresh token.")


class LoginRequest(BaseModel):
    """JSON login body, offered next to the OAuth2 form endpoint."""

    username: str = Field(min_length=3, max_length=50, description="Username or e-mail address.")
    password: str = Field(min_length=1, max_length=72, description="Plain text password.")


class TokenPayload(BaseModel):
    """Decoded JWT claim set."""

    sub: str
    username: str
    role: Role
    type: str
    jti: str
    exp: datetime
    iat: datetime


class PermissionSet(BaseModel):
    """The effective permissions of the calling identity."""

    role: Role
    permissions: list[Permission]
