"""User management endpoints guarded by the RBAC layer.

Method-to-permission mapping:

============================  ==========  =========================================
Endpoint                      Permission  Roles allowed
============================  ==========  =========================================
POST   /users                 USER_REGISTER  superadmin
GET    /users                 READ           every role
GET    /users/{id}            READ           every role
HEAD   /users/{id}            READ           every role
PUT    /users/{id}            UPDATE         superadmin, admin, manager
PATCH  /users/{id}            UPDATE         superadmin, admin, manager
PATCH  /users/{id}/access     ROLE_MANAGE    superadmin, admin
DELETE /users/{id}            DELETE         superadmin, admin
============================  ==========  =========================================
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Response, status

from app.api.deps import ActiveUser, DbSession, Pagination, require_permissions
from app.core.exceptions import AuthorizationError, ValidationError
from app.core.logger import get_logger
from app.core.rbac import Permission, Role, outranks
from app.crud import user as user_crud
from app.models.user import User
from app.schemas.common import Page
from app.schemas.user import (
    UserCreate,
    UserPatch,
    UserRead,
    UserRoleUpdate,
    UserUpdate,
    UserWithPermissions,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/users", tags=["Users"])

UserId = Annotated[int, Path(ge=1, description="Primary key of the target user.")]


def _assert_may_act_on(actor: User, target: User, action: str) -> None:
    """Guard a mutation against privilege escalation between peers.

    A caller may always act on their own account. Acting on somebody else
    requires strictly outranking them, so an admin can never modify or delete
    another admin or a superadmin.

    Args:
        actor: The authenticated caller.
        target: The account being acted upon.
        action: Verb used in the error message.

    Raises:
        AuthorizationError: If the actor does not outrank the target.
    """
    if actor.id == target.id:
        return
    if not outranks(actor.role, target.role):
        raise AuthorizationError(
            f"Role '{actor.role.value}' cannot {action} an account with role "
            f"'{target.role.value}'."
        )


@router.post(
    "",
    response_model=UserWithPermissions,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user (superadmin only)",
)
def register_user(
    session: DbSession,
    payload: UserCreate,
    current_user: Annotated[User, Depends(require_permissions(Permission.USER_REGISTER))],
) -> UserWithPermissions:
    """Create a new account.

    Only the superadmin holds ``user:register``, so admins cannot register users.

    Args:
        session: Active database session.
        payload: Registration data including the role to assign.
        current_user: The authenticated caller.

    Returns:
        The created account with its permission set.
    """
    user = user_crud.create_user(session, payload)
    logger.info(
        "User id=%s registered account id=%s with role=%s",
        current_user.id,
        user.id,
        user.role.value,
    )
    return UserWithPermissions.from_user(user)


@router.get("", response_model=Page[UserRead], summary="List users")
def list_users(
    session: DbSession,
    pagination: Pagination,
    _: Annotated[User, Depends(require_permissions(Permission.READ))],
    role: Annotated[Role | None, Query(description="Filter by role.")] = None,
    is_active: Annotated[bool | None, Query(description="Filter by active flag.")] = None,
    search: Annotated[
        str | None, Query(max_length=100, description="Match username, e-mail or full name.")
    ] = None,
) -> Page[UserRead]:
    """Return a paginated, filterable list of accounts.

    Args:
        session: Active database session.
        pagination: Sanitised ``skip``/``limit`` values.
        _: Authorization guard requiring ``read``.
        role: Optional role filter.
        is_active: Optional active flag filter.
        search: Optional case insensitive text filter.

    Returns:
        One page of accounts plus the total match count.
    """
    users, total = user_crud.list_users(
        session, role=role, is_active=is_active, search=search, **pagination
    )
    return Page[UserRead](
        total=total,
        skip=pagination["skip"],
        limit=pagination["limit"],
        items=[UserRead.model_validate(user) for user in users],
    )


@router.get("/{user_id}", response_model=UserWithPermissions, summary="Retrieve a single user")
def read_user(
    session: DbSession,
    user_id: UserId,
    _: Annotated[User, Depends(require_permissions(Permission.READ))],
) -> UserWithPermissions:
    """Return one account and its effective permissions.

    Args:
        session: Active database session.
        user_id: Primary key of the requested account.
        _: Authorization guard requiring ``read``.

    Returns:
        The requested account.
    """
    return UserWithPermissions.from_user(user_crud.get_user_or_404(session, user_id))


@router.head("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Probe a user's existence")
def head_user(
    session: DbSession,
    user_id: UserId,
    response: Response,
    _: Annotated[User, Depends(require_permissions(Permission.READ))],
) -> Response:
    """Confirm an account exists without transferring its representation.

    Args:
        session: Active database session.
        user_id: Primary key of the requested account.
        response: Response object used to set headers.
        _: Authorization guard requiring ``read``.

    Returns:
        An empty ``204`` response carrying the resource role in a header.
    """
    user = user_crud.get_user_or_404(session, user_id)
    response.headers["X-Resource-Role"] = user.role.value
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.put("/{user_id}", response_model=UserRead, summary="Replace a user profile")
def replace_user(
    session: DbSession,
    user_id: UserId,
    payload: UserUpdate,
    current_user: Annotated[User, Depends(require_permissions(Permission.UPDATE))],
) -> UserRead:
    """Replace the editable profile fields of an account.

    Args:
        session: Active database session.
        user_id: Primary key of the target account.
        payload: Complete replacement profile.
        current_user: The authenticated caller.

    Returns:
        The updated account.
    """
    target = user_crud.get_user_or_404(session, user_id)
    _assert_may_act_on(current_user, target, "update")
    return UserRead.model_validate(user_crud.replace_user(session, target, payload))


@router.patch("/{user_id}", response_model=UserRead, summary="Partially update a user profile")
def patch_user(
    session: DbSession,
    user_id: UserId,
    payload: UserPatch,
    current_user: Annotated[User, Depends(require_permissions(Permission.UPDATE))],
) -> UserRead:
    """Update only the supplied profile fields of an account.

    Args:
        session: Active database session.
        user_id: Primary key of the target account.
        payload: Sparse update payload.
        current_user: The authenticated caller.

    Returns:
        The updated account.
    """
    target = user_crud.get_user_or_404(session, user_id)
    _assert_may_act_on(current_user, target, "update")
    return UserRead.model_validate(user_crud.patch_user(session, target, payload))


@router.patch(
    "/{user_id}/access",
    response_model=UserWithPermissions,
    summary="Change a user's role or active flag",
)
def update_user_access(
    session: DbSession,
    user_id: UserId,
    payload: UserRoleUpdate,
    current_user: Annotated[User, Depends(require_permissions(Permission.ROLE_MANAGE))],
) -> UserWithPermissions:
    """Grant or revoke access by changing the role and/or the active flag.

    Args:
        session: Active database session.
        user_id: Primary key of the target account.
        payload: New role and/or active flag.
        current_user: The authenticated caller.

    Returns:
        The updated account with its new permission set.

    Raises:
        ValidationError: If the payload is empty, if a caller targets their own
            access level, or if the change would remove the last superadmin.
        AuthorizationError: If the caller may not assign the requested role.
    """
    if payload.role is None and payload.is_active is None:
        raise ValidationError("Provide 'role' and/or 'is_active'.")

    target = user_crud.get_user_or_404(session, user_id)
    if target.id == current_user.id:
        raise ValidationError("You cannot change your own role or active flag.")
    _assert_may_act_on(current_user, target, "manage")

    # A caller may assign any role up to and including their own rank, never above it.
    if payload.role is not None and payload.role is not current_user.role:
        if not outranks(current_user.role, payload.role):
            raise AuthorizationError(
                f"Role '{current_user.role.value}' cannot assign the role '{payload.role.value}'."
            )

    losing_superadmin = target.role is Role.SUPERADMIN and (
        (payload.role is not None and payload.role is not Role.SUPERADMIN)
        or payload.is_active is False
    )
    if losing_superadmin and user_crud.count_by_role(session, Role.SUPERADMIN) <= 1:
        raise ValidationError("The last superadmin account must stay active.")

    return UserWithPermissions.from_user(user_crud.update_role(session, target, payload))


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete a user")
def delete_user(
    session: DbSession,
    user_id: UserId,
    current_user: Annotated[User, Depends(require_permissions(Permission.DELETE))],
) -> Response:
    """Delete an account together with the items it owns.

    Args:
        session: Active database session.
        user_id: Primary key of the target account.
        current_user: The authenticated caller.

    Returns:
        An empty ``204`` response.

    Raises:
        ValidationError: If the caller targets their own account or the last superadmin.
    """
    target = user_crud.get_user_or_404(session, user_id)
    if target.id == current_user.id:
        raise ValidationError("You cannot delete your own account.")
    _assert_may_act_on(current_user, target, "delete")
    if target.role is Role.SUPERADMIN and user_crud.count_by_role(session, Role.SUPERADMIN) <= 1:
        raise ValidationError("The last superadmin account cannot be deleted.")

    user_crud.delete_user(session, target)
    logger.info("User id=%s deleted account id=%s", current_user.id, user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.options("", include_in_schema=False)
def users_options(response: Response, current_user: ActiveUser) -> Response:
    """Advertise the methods the caller's role may use on the collection.

    Args:
        response: Response object used to set headers.
        current_user: The authenticated caller.

    Returns:
        An empty ``204`` response with an ``Allow`` header tailored to the role.
    """
    allowed = ["OPTIONS"]
    permissions = current_user.permissions
    if Permission.READ in permissions:
        allowed += ["GET", "HEAD"]
    if Permission.USER_REGISTER in permissions:
        allowed.append("POST")
    if Permission.UPDATE in permissions:
        allowed += ["PUT", "PATCH"]
    if Permission.DELETE in permissions:
        allowed.append("DELETE")
    response.headers["Allow"] = ", ".join(allowed)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
