"""Database operations for items."""

from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.exceptions import DatabaseError, NotFoundError
from app.core.logger import get_logger
from app.models.item import Item
from app.schemas.item import ItemCreate, ItemPatch, ItemUpdate

logger = get_logger(__name__)


def get_item(session: Session, item_id: int) -> Item | None:
    """Return the item with ``item_id`` or ``None``."""
    return session.get(Item, item_id)


def get_item_or_404(session: Session, item_id: int) -> Item:
    """Return the item with ``item_id``.

    Args:
        session: Active database session.
        item_id: Primary key of the requested item.

    Returns:
        The matching item.

    Raises:
        NotFoundError: If no such item exists.
    """
    item = get_item(session, item_id)
    if item is None:
        raise NotFoundError(f"Item {item_id} was not found.")
    return item


def list_items(
    session: Session,
    *,
    skip: int = 0,
    limit: int = 50,
    owner_id: int | None = None,
    is_active: bool | None = None,
    search: str | None = None,
) -> tuple[list[Item], int]:
    """Return a filtered page of items and the total number of matches.

    Args:
        session: Active database session.
        skip: Number of records to skip.
        limit: Maximum number of records to return.
        owner_id: Restrict the result to a single owner.
        is_active: Restrict the result to active or inactive items.
        search: Case insensitive fragment matched against name and description.

    Returns:
        A tuple of ``(items, total_matches)``.
    """
    filters = []
    if owner_id is not None:
        filters.append(Item.owner_id == owner_id)
    if is_active is not None:
        filters.append(Item.is_active.is_(is_active))
    if search:
        pattern = f"%{search.lower()}%"
        filters.append(
            or_(
                func.lower(Item.name).like(pattern),
                func.lower(func.coalesce(Item.description, "")).like(pattern),
            )
        )

    total = session.scalar(select(func.count()).select_from(Item).where(*filters)) or 0
    statement = select(Item).where(*filters).order_by(Item.id).offset(skip).limit(limit)
    return list(session.scalars(statement)), total


def create_item(session: Session, payload: ItemCreate, owner_id: int) -> Item:
    """Persist a new item owned by ``owner_id``.

    Args:
        session: Active database session.
        payload: Validated item data.
        owner_id: Primary key of the owning user.

    Returns:
        The persisted item.

    Raises:
        DatabaseError: If the insert fails.
    """
    item = Item(**payload.model_dump(), owner_id=owner_id)
    try:
        session.add(item)
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        logger.exception("Failed to create item for owner %s.", owner_id)
        raise DatabaseError("Unable to create the item.") from exc
    session.refresh(item)
    logger.info("Created item id=%s owner_id=%s", item.id, owner_id)
    return item


def _commit(session: Session, item: Item, action: str) -> Item:
    """Commit a pending mutation to ``item`` and return the refreshed instance.

    Args:
        session: Active database session.
        item: The instance being mutated.
        action: Verb used in error messages and logs.

    Returns:
        The refreshed item.

    Raises:
        DatabaseError: If the commit fails.
    """
    try:
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        logger.exception("Failed to %s item %s.", action, item.id)
        raise DatabaseError(f"Unable to {action} the item.") from exc
    session.refresh(item)
    return item


def replace_item(session: Session, item: Item, payload: ItemUpdate) -> Item:
    """Overwrite every editable field of ``item`` (``PUT`` semantics).

    Args:
        session: Active database session.
        item: The item being replaced.
        payload: Complete replacement representation.

    Returns:
        The updated item.
    """
    for field, value in payload.model_dump().items():
        setattr(item, field, value)
    updated = _commit(session, item, "update")
    logger.info("Replaced item id=%s", updated.id)
    return updated


def patch_item(session: Session, item: Item, payload: ItemPatch) -> Item:
    """Apply only the fields explicitly provided in ``payload`` (``PATCH`` semantics).

    Args:
        session: Active database session.
        item: The item being updated.
        payload: Sparse update payload.

    Returns:
        The updated item.
    """
    data = payload.model_dump(exclude_unset=True)
    for field, value in data.items():
        # ``description`` is the only nullable field, so an explicit null is kept.
        if value is not None or field == "description":
            setattr(item, field, value)
    updated = _commit(session, item, "update")
    logger.info("Patched item id=%s fields=%s", updated.id, sorted(data))
    return updated


def delete_item(session: Session, item: Item) -> None:
    """Delete ``item``.

    Args:
        session: Active database session.
        item: The item to delete.

    Raises:
        DatabaseError: If the delete fails.
    """
    item_id = item.id
    try:
        session.delete(item)
        session.commit()
    except SQLAlchemyError as exc:
        session.rollback()
        logger.exception("Failed to delete item %s.", item_id)
        raise DatabaseError("Unable to delete the item.") from exc
    logger.info("Deleted item id=%s", item_id)
