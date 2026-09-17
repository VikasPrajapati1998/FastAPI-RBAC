"""Authentication endpoints: login, refresh, logout and identity introspection."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Body, Depends, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import AuthenticationError, TokenError
from app.core.logger import get_logger
from app.core.rbac import permissions_for
from app.core.security import (
    TokenType,
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_password,
)
from app.crud import token as token_crud
from app.crud import user as user_crud
from app.api.deps import ActiveUser, DbSession
from app.models.user import User
from app.schemas.common import Message
from app.schemas.token import LoginRequest, PermissionSet, RefreshRequest, TokenPair
from app.schemas.user import PasswordChange, UserWithPermissions

logger = get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _issue_token_pair(user: User) -> TokenPair:
    """Mint a fresh access/refresh pair for ``user``.

    Args:
        user: The authenticated account.

    Returns:
        The populated :class:`TokenPair` response model.
    """
    access_token, access_expires_at, _ = create_access_token(user.id, user.role.value, user.username)
    refresh_token, refresh_expires_at, _ = create_refresh_token(
        user.id, user.role.value, user.username
    )
    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
        access_token_expires_at=access_expires_at,
        refresh_token_expires_at=refresh_expires_at,
    )


def _authenticate(session: Session, identifier: str, password: str) -> User:
    """Verify credentials and return the matching account.

    Args:
        session: Active database session.
        identifier: Username or e-mail address.
        password: Plain text password.

    Returns:
        The authenticated user.

    Raises:
        AuthenticationError: If the credentials are wrong or the account is inactive.
    """
    user = user_crud.get_by_identifier(session, identifier)
    if user is None or not verify_password(password, user.hashed_password):
        # Identical message for both cases so the response cannot be used to
        # enumerate valid usernames.
        logger.warning("Failed login attempt for identifier=%r", identifier)
        raise AuthenticationError("Incorrect username or password.")
    if not user.is_active:
        logger.warning("Login attempt on deactivated account id=%s", user.id)
        raise AuthenticationError("This account has been deactivated.")
    logger.info("User id=%s username=%s logged in.", user.id, user.username)
    return user


@router.post(
    "/login",
    response_model=TokenPair,
    summary="Obtain a token pair with an OAuth2 form (used by the Swagger UI)",
)
def login_form(
    session: DbSession,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> TokenPair:
    """Authenticate with ``application/x-www-form-urlencoded`` credentials.

    Args:
        session: Active database session.
        form_data: The standard OAuth2 password grant form.

    Returns:
        A fresh access/refresh token pair.
    """
    user = _authenticate(session, form_data.username, form_data.password)
    return _issue_token_pair(user)


@router.post("/login/json", response_model=TokenPair, summary="Obtain a token pair with JSON")
def login_json(session: DbSession, payload: LoginRequest) -> TokenPair:
    """Authenticate with a JSON body.

    Args:
        session: Active database session.
        payload: Username (or e-mail) and password.

    Returns:
        A fresh access/refresh token pair.
    """
    user = _authenticate(session, payload.username, payload.password)
    return _issue_token_pair(user)


@router.post("/refresh", response_model=TokenPair, summary="Exchange a refresh token")
def refresh_tokens(session: DbSession, payload: RefreshRequest) -> TokenPair:
    """Rotate a refresh token into a brand new token pair.

    The presented refresh token is revoked, so every refresh token can be used
    exactly once.

    Args:
        session: Active database session.
        payload: The refresh token to exchange.

    Returns:
        A fresh access/refresh token pair.

    Raises:
        TokenError: If the refresh token is invalid, expired or already used.
        AuthenticationError: If the linked account is gone or deactivated.
    """
    claims = decode_token(payload.refresh_token, TokenType.REFRESH)
    jti = str(claims["jti"])
    if token_crud.is_revoked(session, jti):
        raise TokenError("This refresh token has already been used or revoked.")

    user = user_crud.get_user(session, int(claims["sub"]))
    if user is None:
        raise AuthenticationError("The account linked to this token no longer exists.")
    if not user.is_active:
        raise AuthenticationError("This account has been deactivated.")

    token_crud.revoke(
        session,
        jti=jti,
        token_type=TokenType.REFRESH,
        expires_at=datetime.fromtimestamp(float(claims["exp"]), tz=timezone.utc),
        user_id=user.id,
    )
    logger.info("Rotated refresh token for user id=%s", user.id)
    return _issue_token_pair(user)


@router.post("/logout", response_model=Message, summary="Revoke the presented tokens")
def logout(
    session: DbSession,
    current_user: ActiveUser,
    refresh_token: Annotated[
        str | None,
        Body(embed=True, description="Optional refresh token to revoke alongside the access token."),
    ] = None,
) -> Message:
    """Revoke the caller's refresh token so it can no longer mint access tokens.

    The short lived access token is left to expire naturally (5 minutes by default);
    pass its refresh token here to end the session immediately.

    Args:
        session: Active database session.
        current_user: The authenticated caller.
        refresh_token: The refresh token issued alongside the current access token.

    Returns:
        An acknowledgement message.
    """
    revoked_refresh = False
    if refresh_token:
        claims = decode_token(refresh_token, TokenType.REFRESH)
        if int(claims["sub"]) != current_user.id:
            raise TokenError("The refresh token does not belong to the authenticated user.")
        token_crud.revoke(
            session,
            jti=str(claims["jti"]),
            token_type=TokenType.REFRESH,
            expires_at=datetime.fromtimestamp(float(claims["exp"]), tz=timezone.utc),
            user_id=current_user.id,
        )
        revoked_refresh = True

    logger.info("User id=%s logged out (refresh revoked=%s)", current_user.id, revoked_refresh)
    return Message(
        detail=(
            "Logged out; the refresh token has been revoked."
            if revoked_refresh
            else "Logged out; the access token will expire shortly."
        )
    )


@router.get("/me", response_model=UserWithPermissions, summary="Describe the current identity")
def read_current_user(current_user: ActiveUser) -> UserWithPermissions:
    """Return the caller's profile together with their effective permissions.

    Args:
        current_user: The authenticated caller.

    Returns:
        The caller's account and permission set.
    """
    return UserWithPermissions.from_user(current_user)


@router.get("/me/permissions", response_model=PermissionSet, summary="List effective permissions")
def read_current_permissions(current_user: ActiveUser) -> PermissionSet:
    """Return only the role and permission set of the caller.

    Args:
        current_user: The authenticated caller.

    Returns:
        The caller's role and its permissions.
    """
    return PermissionSet(role=current_user.role, permissions=sorted(permissions_for(current_user.role)))


@router.patch(
    "/me/password",
    response_model=Message,
    summary="Change your own password",
    status_code=status.HTTP_200_OK,
)
def change_own_password(
    session: DbSession, current_user: ActiveUser, payload: PasswordChange
) -> Message:
    """Rotate the caller's own password after verifying the current one.

    Args:
        session: Active database session.
        current_user: The authenticated caller.
        payload: Current and new password.

    Returns:
        An acknowledgement message.

    Raises:
        AuthenticationError: If the current password is wrong.
    """
    if not verify_password(payload.current_password, current_user.hashed_password):
        logger.warning("User id=%s supplied a wrong current password.", current_user.id)
        raise AuthenticationError("The current password is incorrect.")
    user_crud.set_password(session, current_user, payload.new_password)
    logger.info("User id=%s changed their password.", current_user.id)
    return Message(detail="Password updated successfully.")


@router.options("/login", include_in_schema=False)
def login_options(response: Response) -> Response:
    """Advertise the methods supported by the login endpoint."""
    response.headers["Allow"] = "POST, OPTIONS"
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
