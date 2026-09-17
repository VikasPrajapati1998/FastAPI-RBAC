"""Item endpoints exposing every HTTP method behind the RBAC layer.

============================  ==========  =========================================
Endpoint                      Permission  Roles allowed
============================  ==========  =========================================
GET     /items                READ        every role
HEAD    /items/{id}           READ        every role
GET     /items/{id}           READ        every role
POST    /items                WRITE       superadmin, admin, manager, supervisor
PUT     /items/{id}           UPDATE      superadmin, admin, manager
PATCH   /items/{id}           UPDATE      superadmin, admin, manager
DELETE  /items/{id}           DELETE      superadmin, admin
OPTIONS /items                (any)       every role (reports its own Allow header)
============================  ==========  =========================================
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Response, status

from app.api.deps import ActiveUser, DbSession, Pagination, require_permissions
from app.core.logger import get_logger
from app.core.rbac import Permission
from app.crud import item as item_crud
from app.models.user import User
from app.schemas.common import Page
from app.schemas.item import ItemCreate, ItemPatch, ItemRead, ItemUpdate

logger = get_logger(__name__)

router = APIRouter(prefix="/items", tags=["Items"])

ItemId = Annotated[int, Path(ge=1, description="Primary key of the target item.")]


@router.get("", response_model=Page[ItemRead], summary="List items (read)")
def list_items(
    session: DbSession,
    pagination: Pagination,
    _: Annotated[User, Depends(require_permissions(Permission.READ))],
    owner_id: Annotated[int | None, Query(ge=1, description="Filter by owner.")] = None,
    is_active: Annotated[bool | None, Query(description="Filter by active flag.")] = None,
    search: Annotated[
        str | None, Query(max_length=100, description="Match name or description.")
    ] = None,
) -> Page[ItemRead]:
    """Return a paginated, filterable list of items.

    Args:
        session: Active database session.
        pagination: Sanitised ``skip``/``limit`` values.
        _: Authorization guard requiring ``read``.
        owner_id: Optional owner filter.
        is_active: Optional active flag filter.
        search: Optional case insensitive text filter.

    Returns:
        One page of items plus the total match count.
    """
    items, total = item_crud.list_items(
        session, owner_id=owner_id, is_active=is_active, search=search, **pagination
    )
    return Page[ItemRead](
        total=total,
        skip=pagination["skip"],
        limit=pagination["limit"],
        items=[ItemRead.model_validate(item) for item in items],
    )


@router.get("/{item_id}", response_model=ItemRead, summary="Retrieve one item (read)")
def read_item(
    session: DbSession,
    item_id: ItemId,
    _: Annotated[User, Depends(require_permissions(Permission.READ))],
) -> ItemRead:
    """Return a single item.

    Args:
        session: Active database session.
        item_id: Primary key of the requested item.
        _: Authorization guard requiring ``read``.

    Returns:
        The requested item.
    """
    return ItemRead.model_validate(item_crud.get_item_or_404(session, item_id))


@router.head(
    "/{item_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Probe an item's existence (read)"
)
def head_item(
    session: DbSession,
    item_id: ItemId,
    response: Response,
    _: Annotated[User, Depends(require_permissions(Permission.READ))],
) -> Response:
    """Confirm an item exists without transferring its representation.

    Args:
        session: Active database session.
        item_id: Primary key of the requested item.
        response: Response object used to set headers.
        _: Authorization guard requiring ``read``.

    Returns:
        An empty ``204`` response carrying the last modification timestamp.
    """
    item = item_crud.get_item_or_404(session, item_id)
    response.headers["X-Resource-Updated-At"] = item.updated_at.isoformat()
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.post(
    "",
    response_model=ItemRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create an item (write)",
)
def create_item(
    session: DbSession,
    payload: ItemCreate,
    current_user: Annotated[User, Depends(require_permissions(Permission.WRITE))],
) -> ItemRead:
    """Create an item owned by the caller.

    Args:
        session: Active database session.
        payload: Item data.
        current_user: The authenticated caller, who becomes the owner.

    Returns:
        The created item.
    """
    item = item_crud.create_item(session, payload, owner_id=current_user.id)
    logger.info("User id=%s created item id=%s", current_user.id, item.id)
    return ItemRead.model_validate(item)


@router.put("/{item_id}", response_model=ItemRead, summary="Replace an item (update)")
def replace_item(
    session: DbSession,
    item_id: ItemId,
    payload: ItemUpdate,
    current_user: Annotated[User, Depends(require_permissions(Permission.UPDATE))],
) -> ItemRead:
    """Overwrite every editable field of an item.

    Args:
        session: Active database session.
        item_id: Primary key of the target item.
        payload: Complete replacement representation.
        current_user: The authenticated caller.

    Returns:
        The updated item.
    """
    item = item_crud.get_item_or_404(session, item_id)
    updated = item_crud.replace_item(session, item, payload)
    logger.info("User id=%s replaced item id=%s", current_user.id, item_id)
    return ItemRead.model_validate(updated)


@router.patch("/{item_id}", response_model=ItemRead, summary="Partially update an item (update)")
def patch_item(
    session: DbSession,
    item_id: ItemId,
    payload: ItemPatch,
    current_user: Annotated[User, Depends(require_permissions(Permission.UPDATE))],
) -> ItemRead:
    """Update only the fields supplied in the payload.

    Args:
        session: Active database session.
        item_id: Primary key of the target item.
        payload: Sparse update payload.
        current_user: The authenticated caller.

    Returns:
        The updated item.
    """
    item = item_crud.get_item_or_404(session, item_id)
    updated = item_crud.patch_item(session, item, payload)
    logger.info("User id=%s patched item id=%s", current_user.id, item_id)
    return ItemRead.model_validate(updated)


@router.delete(
    "/{item_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Delete an item (delete)"
)
def delete_item(
    session: DbSession,
    item_id: ItemId,
    current_user: Annotated[User, Depends(require_permissions(Permission.DELETE))],
) -> Response:
    """Delete an item permanently.

    Args:
        session: Active database session.
        item_id: Primary key of the target item.
        current_user: The authenticated caller.

    Returns:
        An empty ``204`` response.
    """
    item = item_crud.get_item_or_404(session, item_id)
    item_crud.delete_item(session, item)
    logger.info("User id=%s deleted item id=%s", current_user.id, item_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.options("", include_in_schema=False)
def items_options(response: Response, current_user: ActiveUser) -> Response:
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
    if Permission.WRITE in permissions:
        allowed.append("POST")
    if Permission.UPDATE in permissions:
        allowed += ["PUT", "PATCH"]
    if Permission.DELETE in permissions:
        allowed.append("DELETE")
    response.headers["Allow"] = ", ".join(allowed)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
