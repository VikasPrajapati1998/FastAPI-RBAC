"""Database operations for the revoked token registry."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.exceptions import DatabaseError
from app.core.logger import get_logger
from app.core.security import TokenType
from app.models.revoked_token import RevokedToken

logger = get_logger(__name__)


def is_revoked(session: Session, jti: str) -> bool:
    """Report whether the token identified by ``jti`` has been revoked.

    Args:
        session: Active database session.
        jti: The JWT identifier claim.

    Returns:
        ``True`` when a revocation record exists.
    """
    return session.scalar(select(RevokedToken.id).where(RevokedToken.jti == jti)) is not None


def revoke(
    session: Session,
    *,
    jti: str,
    token_type: TokenType,
    expires_at: datetime,
    user_id: int | None,
) -> None:
    """Record a token identifier as revoked.

    Revoking the same ``jti`` twice is a no-op rather than an error, so repeated
    logout calls stay idempotent.

    Args:
        session: Active database session.
        jti: The JWT identifier claim.
        token_type: Whether an access or a refresh token is revoked.
        expires_at: Natural expiry of the token, used later for pruning.
        user_id: Owner of the token, when known.

    Raises:
        DatabaseError: If the insert fails.
    """
    record = RevokedToken(
        jti=jti, token_type=token_type.value, expires_at=expires_at, user_id=user_id
    )
    try:
        session.add(record)
        session.commit()
    except IntegrityError:
        session.rollback()
        logger.debug("Token jti=%s was already revoked.", jti)
        return
    except SQLAlchemyError as exc:
        session.rollback()
        logger.exception("Failed to revoke token jti=%s.", jti)
        raise DatabaseError("Unable to revoke the token.") from exc
    logger.info("Revoked %s token jti=%s user_id=%s", token_type.value, jti, user_id)


def purge_expired(session: Session) -> int:
    """Delete revocation records whose tokens have expired anyway.

    Args:
        session: Active database session.

    Returns:
        The number of rows removed.

    Raises:
        DatabaseError: If the delete fails.
    """
    try:
        result = session.execute(
            delete(RevokedToken).where(RevokedToken.expires_at < datetime.now(timezone.utc))
        )
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        logger.exception("Failed to purge expired revocation records.")
        raise DatabaseError("Unable to purge expired token records.") from exc
    removed = result.rowcount or 0
    if removed:
        logger.info("Purged %s expired revocation record(s).", removed)
    return removed
