"""Password hashing and JWT creation/verification.

Passwords are hashed with bcrypt. Tokens are signed with PyJWT (HS256 by
default) and carry the claims the API needs to authorise a request without a
database round trip for the role. Access and refresh tokens are signed with
*different* secrets so a refresh token can never be replayed as an access token.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Any, Final

import bcrypt
import jwt

from app.core.config import settings
from app.core.exceptions import TokenError, ValidationError
from app.core.logger import get_logger

logger = get_logger(__name__)

_BCRYPT_MAX_BYTES: Final[int] = 72
"""bcrypt silently truncates anything longer, so longer input is rejected."""


class TokenType(StrEnum):
    """Discriminator stored in the ``type`` claim of every token."""

    ACCESS = "access"
    REFRESH = "refresh"


def hash_password(password: str) -> str:
    """Hash a plain text password with bcrypt.

    Args:
        password: The plain text password.

    Returns:
        The bcrypt hash as an ASCII string.

    Raises:
        ValidationError: If the password is empty or exceeds bcrypt's 72 byte limit.
    """
    if not password:
        raise ValidationError("Password must not be empty.")
    encoded = password.encode("utf-8")
    if len(encoded) > _BCRYPT_MAX_BYTES:
        raise ValidationError(f"Password must not exceed {_BCRYPT_MAX_BYTES} bytes.")
    return bcrypt.hashpw(encoded, bcrypt.gensalt()).decode("ascii")


def verify_password(password: str, hashed_password: str) -> bool:
    """Check a plain text password against a stored bcrypt hash.

    Args:
        password: The plain text password supplied by the caller.
        hashed_password: The stored bcrypt hash.

    Returns:
        ``True`` when the password matches the hash.
    """
    try:
        return bcrypt.checkpw(password.encode("utf-8")[:_BCRYPT_MAX_BYTES], hashed_password.encode("utf-8"))
    except ValueError:
        # Malformed hash in storage: treat as a failed login rather than a crash.
        logger.warning("Rejected a login attempt against a malformed password hash.")
        return False


def _secret_for(token_type: TokenType) -> str:
    """Return the signing secret used for ``token_type``."""
    if token_type is TokenType.REFRESH:
        return settings.jwt_refresh_secret_key
    return settings.jwt_secret_key


def _lifetime_for(token_type: TokenType) -> timedelta:
    """Return the configured lifetime of ``token_type``."""
    if token_type is TokenType.REFRESH:
        return timedelta(minutes=settings.refresh_token_expire_minutes)
    return timedelta(minutes=settings.access_token_expire_minutes)


def create_token(
    subject: int | str,
    role: str,
    username: str,
    token_type: TokenType,
    expires_delta: timedelta | None = None,
) -> tuple[str, datetime, str]:
    """Create a signed JWT.

    Args:
        subject: Primary key of the user the token represents.
        role: Role name embedded in the token.
        username: Username embedded in the token for auditing.
        token_type: Whether an access or a refresh token is issued.
        expires_delta: Overrides the configured lifetime when provided.

    Returns:
        A tuple of ``(encoded_token, expiry_datetime, jti)``.
    """
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + (expires_delta or _lifetime_for(token_type))
    jti = str(uuid.uuid4())
    payload: dict[str, Any] = {
        "sub": str(subject),
        "username": username,
        "role": role,
        "type": token_type.value,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": expires_at,
        "jti": jti,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }
    encoded = jwt.encode(payload, _secret_for(token_type), algorithm=settings.jwt_algorithm)
    return encoded, expires_at, jti


def create_access_token(subject: int | str, role: str, username: str) -> tuple[str, datetime, str]:
    """Create a short lived access token (5 minutes by default)."""
    return create_token(subject, role, username, TokenType.ACCESS)


def create_refresh_token(subject: int | str, role: str, username: str) -> tuple[str, datetime, str]:
    """Create a long lived refresh token used to mint new access tokens."""
    return create_token(subject, role, username, TokenType.REFRESH)


def decode_token(token: str, expected_type: TokenType) -> dict[str, Any]:
    """Decode and validate a JWT.

    Args:
        token: The encoded JWT.
        expected_type: The token type the caller requires.

    Returns:
        The decoded claim set.

    Raises:
        TokenError: If the token is expired, malformed, signed with the wrong key,
            issued for a different audience, or is not of ``expected_type``.
    """
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            _secret_for(expected_type),
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            options={"require": ["exp", "iat", "sub", "jti", "type"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenError(f"The {expected_type.value} token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenError(f"The {expected_type.value} token is invalid.") from exc

    if claims.get("type") != expected_type.value:
        raise TokenError(f"Expected a {expected_type.value} token.")
    return claims
