"""Database operations for user accounts."""

from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, DatabaseError, NotFoundError
from app.core.logger import get_logger
from app.core.rbac import Role
from app.core.security import hash_password
from app.models.user import User
from app.schemas.user import UserCreate, UserPatch, UserRoleUpdate, UserUpdate

logger = get_logger(__name__)


def get_user(session: Session, user_id: int) -> User | None:
    """Return the user with ``user_id`` or ``None``."""
    return session.get(User, user_id)


def get_user_or_404(session: Session, user_id: int) -> User:
    """Return the user with ``user_id``.

    Args:
        session: Active database session.
        user_id: Primary key of the requested user.

    Returns:
        The matching user.

    Raises:
        NotFoundError: If no such user exists.
    """
    user = get_user(session, user_id)
    if user is None:
        raise NotFoundError(f"User {user_id} was not found.")
    return user


def get_by_username(session: Session, username: str) -> User | None:
    """Return the user with the given username or ``None``."""
    return session.scalar(select(User).where(User.username == username))


def get_by_email(session: Session, email: str) -> User | None:
    """Return the user with the given e-mail address or ``None``."""
    return session.scalar(select(User).where(User.email == email))


def get_by_identifier(session: Session, identifier: str) -> User | None:
    """Return the user matching either the username or the e-mail address."""
    statement = select(User).where(or_(User.username == identifier, User.email == identifier))
    return session.scalar(statement)


def list_users(
    session: Session,
    *,
    skip: int = 0,
    limit: int = 50,
    role: Role | None = None,
    is_active: bool | None = None,
    search: str | None = None,
) -> tuple[list[User], int]:
    """Return a filtered page of users and the total number of matches.

    Args:
        session: Active database session.
        skip: Number of records to skip.
        limit: Maximum number of records to return.
        role: Restrict the result to a single role.
        is_active: Restrict the result to active or inactive accounts.
        search: Case insensitive fragment matched against username, e-mail and full name.

    Returns:
        A tuple of ``(users, total_matches)``.
    """
    filters = []
    if role is not None:
        filters.append(User.role == role)
    if is_active is not None:
        filters.append(User.is_active.is_(is_active))
    if search:
        pattern = f"%{search.lower()}%"
        filters.append(
            or_(
                func.lower(User.username).like(pattern),
                func.lower(User.email).like(pattern),
                func.lower(func.coalesce(User.full_name, "")).like(pattern),
            )
        )

    total = session.scalar(select(func.count()).select_from(User).where(*filters)) or 0
    statement = select(User).where(*filters).order_by(User.id).offset(skip).limit(limit)
    return list(session.scalars(statement)), total


def create_user(session: Session, payload: UserCreate) -> User:
    """Persist a new user account.

    Args:
        session: Active database session.
        payload: Validated registration data.

    Returns:
        The persisted user.

    Raises:
        ConflictError: If the username or e-mail address is already taken.
        DatabaseError: If the insert fails for any other reason.
    """
    if get_by_username(session, payload.username) is not None:
        raise ConflictError(f"Username '{payload.username}' is already taken.")
    if get_by_email(session, str(payload.email)) is not None:
        raise ConflictError(f"E-mail '{payload.email}' is already registered.")

    user = User(
        username=payload.username,
        email=str(payload.email),
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        is_active=payload.is_active,
    )
    try:
        session.add(user)
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise ConflictError("A user with those unique fields already exists.") from exc
    except SQLAlchemyError as exc:
        session.rollback()
        logger.exception("Failed to create user %s.", payload.username)
        raise DatabaseError("Unable to create the user.") from exc

    session.refresh(user)
    logger.info("Created user id=%s username=%s role=%s", user.id, user.username, user.role.value)
    return user


def _commit(session: Session, user: User, action: str) -> User:
    """Commit a pending mutation to ``user`` and return the refreshed instance.

    Args:
        session: Active database session.
        user: The instance being mutated.
        action: Verb used in error messages and logs.

    Returns:
        The refreshed user.

    Raises:
        ConflictError: If the change violates a uniqueness constraint.
        DatabaseError: If the commit fails for any other reason.
    """
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise ConflictError("The requested change conflicts with an existing user.") from exc
    except SQLAlchemyError as exc:
        session.rollback()
        logger.exception("Failed to %s user %s.", action, user.id)
        raise DatabaseError(f"Unable to {action} the user.") from exc
    session.refresh(user)
    return user


def replace_user(session: Session, user: User, payload: UserUpdate) -> User:
    """Replace the editable profile fields of ``user`` (``PUT`` semantics).

    Args:
        session: Active database session.
        user: The account being updated.
        payload: Complete replacement profile.

    Returns:
        The updated user.

    Raises:
        ConflictError: If the new e-mail address belongs to another account.
    """
    existing = get_by_email(session, str(payload.email))
    if existing is not None and existing.id != user.id:
        raise ConflictError(f"E-mail '{payload.email}' is already registered.")
    user.email = str(payload.email)
    user.full_name = payload.full_name
    return _commit(session, user, "update")


def patch_user(session: Session, user: User, payload: UserPatch) -> User:
    """Apply only the fields explicitly provided in ``payload`` (``PATCH`` semantics).

    Args:
        session: Active database session.
        user: The account being updated.
        payload: Sparse update payload.

    Returns:
        The updated user.

    Raises:
        ConflictError: If the new e-mail address belongs to another account.
    """
    data = payload.model_dump(exclude_unset=True)

    new_email = data.pop("email", None)
    if new_email is not None:
        existing = get_by_email(session, str(new_email))
        if existing is not None and existing.id != user.id:
            raise ConflictError(f"E-mail '{new_email}' is already registered.")
        user.email = str(new_email)

    new_password = data.pop("password", None)
    if new_password is not None:
        user.hashed_password = hash_password(new_password)

    if "full_name" in data:
        # Explicit ``null`` is a meaningful value for this optional field.
        user.full_name = data["full_name"]

    return _commit(session, user, "update")


def update_role(session: Session, user: User, payload: UserRoleUpdate) -> User:
    """Change the role and/or the active flag of ``user``.

    Args:
        session: Active database session.
        user: The account being updated.
        payload: New role and/or active flag.

    Returns:
        The updated user.
    """
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
    updated = _commit(session, user, "update")
    logger.info(
        "Updated access for user id=%s role=%s is_active=%s",
        updated.id,
        updated.role.value,
        updated.is_active,
    )
    return updated


def set_password(session: Session, user: User, new_password: str) -> User:
    """Replace the stored password hash of ``user``."""
    user.hashed_password = hash_password(new_password)
    return _commit(session, user, "update")


def delete_user(session: Session, user: User) -> None:
    """Delete ``user`` and, by cascade, every item they own.

    Args:
        session: Active database session.
        user: The account to delete.

    Raises:
        DatabaseError: If the delete fails.
    """
    user_id = user.id
    try:
        session.delete(user)
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        logger.exception("Failed to delete user %s.", user_id)
        raise DatabaseError("Unable to delete the user.") from exc
    logger.info("Deleted user id=%s", user_id)


def count_by_role(session: Session, role: Role) -> int:
    """Return the number of accounts currently holding ``role``."""
    return session.scalar(select(func.count()).select_from(User).where(User.role == role)) or 0
