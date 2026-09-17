"""Reusable FastAPI dependencies for authentication and authorization.

Endpoints never inspect roles by hand. They declare what they need::

    @router.delete("/{item_id}")
    def delete(user: Annotated[User, Depends(require_permissions(Permission.DELETE))]): ...

which keeps the role matrix in :mod:`app.core.rbac` the single source of truth.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    TokenError,
)
from app.core.logger import get_logger
from app.core.rbac import Permission, Role, has_all_permissions
from app.core.security import TokenType, decode_token
from app.crud import token as token_crud
from app.crud import user as user_crud
from app.db.session import get_db
from app.models.user import User

logger = get_logger(__name__)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.api_v1_prefix}/auth/login",
    scheme_name="JWT Bearer",
    auto_error=False,
    description="Paste the access token returned by /auth/login.",
)

DbSession = Annotated[Session, Depends(get_db)]


def _bypass_user(request: Request, session: Session) -> User:
    """Return the stand-in identity used while authentication is disabled.

    Args:
        request: The incoming request, used to attach identity to request state.
        session: Active database session.

    Returns:
        The account named by ``AUTH_BYPASS_USERNAME``.

    Raises:
        ConfigurationError: If that account does not exist, since the request has
            no other identity to fall back on.
    """
    user = user_crud.get_by_identifier(session, settings.auth_bypass_username)
    if user is None:
        raise ConfigurationError(
            f"Authentication is disabled but the bypass account "
            f"'{settings.auth_bypass_username}' does not exist. Set AUTH_BYPASS_USERNAME "
            f"to an existing user or re-enable AUTHENTICATION_ENABLED."
        )
    logger.warning(
        "Authentication disabled: serving %s %s as '%s'.",
        request.method,
        request.url.path,
        user.username,
    )
    request.state.user_id = user.id
    request.state.user_role = user.role.value
    return user


def get_current_user(
    request: Request,
    session: DbSession,
    token: Annotated[str | None, Depends(oauth2_scheme)],
) -> User:
    """Resolve the caller from the ``Authorization: Bearer <token>`` header.

    When ``AUTHENTICATION_ENABLED`` is false the token is ignored entirely and the
    request is attributed to ``AUTH_BYPASS_USERNAME`` instead.

    Args:
        request: The incoming request, used to attach identity to request state.
        session: Active database session.
        token: The raw bearer token extracted by the OAuth2 scheme.

    Returns:
        The authenticated, active user.

    Raises:
        AuthenticationError: If the header is missing or the account no longer exists.
        TokenError: If the token is expired, invalid or revoked.
        ConfigurationError: If authentication is disabled and the bypass account is missing.
    """
    if not settings.authentication_enabled:
        return _bypass_user(request, session)

    if not token:
        raise AuthenticationError("Authentication credentials were not provided.")

    claims = decode_token(token, TokenType.ACCESS)
    jti = str(claims["jti"])
    if token_crud.is_revoked(session, jti):
        raise TokenError("This token has been revoked. Please log in again.")

    try:
        user_id = int(claims["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise TokenError("The token subject is malformed.") from exc

    user = user_crud.get_user(session, user_id)
    if user is None:
        raise AuthenticationError("The account linked to this token no longer exists.")

    if user.role.value != claims.get("role"):
        # The role changed after the token was issued: force a refresh so the
        # caller can never keep using stale, more permissive claims.
        raise TokenError("Your access level changed. Please refresh your token.")

    request.state.user_id = user.id
    request.state.user_role = user.role.value
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_current_active_user(user: CurrentUser) -> User:
    """Ensure the authenticated user has not been deactivated.

    Args:
        user: The authenticated user.

    Returns:
        The same user when the account is active.

    Raises:
        AuthenticationError: If the account is deactivated.
    """
    if not user.is_active:
        raise AuthenticationError("This account has been deactivated.")
    return user


ActiveUser = Annotated[User, Depends(get_current_active_user)]


def require_permissions(*permissions: Permission) -> Callable[[User], User]:
    """Build a dependency that admits only callers holding every listed permission.

    Args:
        *permissions: Permissions the endpoint requires.

    Returns:
        A FastAPI dependency returning the authenticated user.
    """
    required = frozenset(permissions)

    def dependency(user: ActiveUser) -> User:
        """Authorise the caller against the required permission set.

        Raises:
            AuthorizationError: If the caller's role lacks any required permission.
        """
        if not settings.authorization_enabled:
            logger.warning(
                "Authorization disabled: granting user id=%s role=%s the permission(s) %s.",
                user.id,
                user.role.value,
                sorted(perm.value for perm in required),
            )
            return user

        if not has_all_permissions(user.role, required):
            missing = sorted(perm.value for perm in required - user.permissions)
            logger.warning(
                "Denied user id=%s role=%s: missing permission(s) %s",
                user.id,
                user.role.value,
                missing,
            )
            raise AuthorizationError(
                f"Role '{user.role.value}' is not allowed to perform this action.",
                details={"required": sorted(perm.value for perm in required), "missing": missing},
            )
        return user

    return dependency


def require_roles(*roles: Role) -> Callable[[User], User]:
    """Build a dependency that admits only the listed roles.

    Prefer :func:`require_permissions`; use this only when an endpoint is tied to a
    specific role rather than to a capability.

    Args:
        *roles: Roles allowed to call the endpoint.

    Returns:
        A FastAPI dependency returning the authenticated user.
    """
    allowed = frozenset(roles)

    def dependency(user: ActiveUser) -> User:
        """Authorise the caller against the allowed role set.

        Raises:
            AuthorizationError: If the caller's role is not in the allow list.
        """
        if not settings.authorization_enabled:
            logger.warning(
                "Authorization disabled: admitting user id=%s role=%s to a %s endpoint.",
                user.id,
                user.role.value,
                sorted(role.value for role in allowed),
            )
            return user

        if user.role not in allowed:
            logger.warning(
                "Denied user id=%s role=%s: role not in %s",
                user.id,
                user.role.value,
                sorted(role.value for role in allowed),
            )
            raise AuthorizationError(
                "This endpoint is restricted to: "
                + ", ".join(sorted(role.value for role in allowed))
            )
        return user

    return dependency


def pagination(skip: int = 0, limit: int = 50) -> dict[str, int]:
    """Validate and normalise pagination query parameters.

    Args:
        skip: Number of records to skip; negative values are clamped to zero.
        limit: Page size, clamped to the range 1-200.

    Returns:
        A mapping with the sanitised ``skip`` and ``limit`` values.
    """
    return {"skip": max(skip, 0), "limit": min(max(limit, 1), 200)}


Pagination = Annotated[dict[str, int], Depends(pagination)]
