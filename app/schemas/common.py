"""Shared response envelopes."""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

ItemT = TypeVar("ItemT")


class Page(BaseModel, Generic[ItemT]):
    """A single page of results."""

    total: int = Field(description="Total number of matching records.")
    skip: int = Field(description="Number of records skipped.")
    limit: int = Field(description="Maximum number of records returned.")
    items: list[ItemT] = Field(description="The records in this page.")


class Message(BaseModel):
    """A simple acknowledgement payload."""

    detail: str


class HealthStatus(BaseModel):
    """Service health response."""

    status: str
    application: str
    version: str
    database: str
    authentication: str = Field(description="'enabled' or 'disabled' (AUTHENTICATION_ENABLED).")
    authorization: str = Field(description="'enabled' or 'disabled' (AUTHORIZATION_ENABLED).")
