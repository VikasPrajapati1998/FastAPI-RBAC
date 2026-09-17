"""Item request and response schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ItemBase(BaseModel):
    """Fields shared by item input schemas."""

    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    quantity: int = Field(default=0, ge=0)
    price: float = Field(default=0.0, ge=0)
    is_active: bool = Field(default=True)


class ItemCreate(ItemBase):
    """Payload accepted by ``POST /items`` (requires ``write``)."""


class ItemUpdate(ItemBase):
    """Full replacement payload for ``PUT /items/{item_id}`` (requires ``update``)."""


class ItemPatch(BaseModel):
    """Partial payload for ``PATCH /items/{item_id}``; unset fields are ignored."""

    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    quantity: int | None = Field(default=None, ge=0)
    price: float | None = Field(default=None, ge=0)
    is_active: bool | None = None


class ItemRead(ItemBase):
    """Public representation of an item."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    owner_id: int
    created_at: datetime
    updated_at: datetime
