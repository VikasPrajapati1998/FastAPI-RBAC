"""Schema creation and first run bootstrapping."""

from __future__ import annotations

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import DatabaseError
from app.core.logger import get_logger
from app.core.rbac import Role
from app.core.security import hash_password, verify_password
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.models import Item, RevokedToken, User  # noqa: F401  (registers the tables)

logger = get_logger(__name__)


def create_tables() -> None:
    """Create every table that does not exist yet.

    Raises:
        DatabaseError: If the schema cannot be created.
    """
    try:
        Base.metadata.create_all(bind=engine)
    except SQLAlchemyError as exc:
        logger.exception("Failed to create the database schema.")
        raise DatabaseError("Unable to initialise the database schema.") from exc
    logger.info("Database schema verified for %s", settings.database_url)


def ensure_superadmin(session: Session) -> User:
    """Create the bootstrap superadmin when no superadmin exists yet.

    The password comes from ``FIRST_SUPERADMIN_PASSWORD`` and is never stored in
    source control. An existing superadmin is returned untouched, so restarting
    the application never resets credentials.

    Args:
        session: Active database session.

    Returns:
        The existing or newly created superadmin account.

    Raises:
        DatabaseError: If the account cannot be created.
    """
    existing = (
        session.query(User).filter(User.role == Role.SUPERADMIN).order_by(User.id).first()
    )
    if existing is not None:
        logger.info("Superadmin already present (id=%s).", existing.id)
        # Editing FIRST_SUPERADMIN_* in .env does NOT update an account that already
        # exists, which silently locks people out. Say so loudly instead.
        if not verify_password(settings.first_superadmin_password, existing.hashed_password):
            logger.warning(
                "FIRST_SUPERADMIN_PASSWORD in .env does not match the stored password for "
                "'%s'. Changing .env never updates an existing account. Run "
                "'python -m app.cli sync-superadmin' to apply the .env values, or log in "
                "with the original password.",
                existing.username,
            )
        return existing

    superadmin = User(
        username=settings.first_superadmin_username,
        email=settings.first_superadmin_email,
        full_name="Platform Superadmin",
        hashed_password=hash_password(settings.first_superadmin_password),
        role=Role.SUPERADMIN,
        is_active=True,
    )
    try:
        session.add(superadmin)
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        logger.exception("Failed to create the bootstrap superadmin.")
        raise DatabaseError("Unable to create the bootstrap superadmin.") from exc

    session.refresh(superadmin)
    logger.warning(
        "Created bootstrap superadmin '%s'. Change its password immediately.",
        superadmin.username,
    )
    return superadmin


def init_db() -> None:
    """Create the schema and guarantee a superadmin exists."""
    create_tables()
    session = SessionLocal()
    try:
        ensure_superadmin(session)
    finally:
        session.close()
