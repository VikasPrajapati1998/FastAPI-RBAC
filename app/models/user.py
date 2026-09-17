"""User account model."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Enum as SQLEnum, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.rbac import Permission, Role, permissions_for
from app.db.base import Base, TimestampMixin

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.models.item import Item


class User(Base, TimestampMixin):
    """An authenticated principal with exactly one role."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(150), nullable=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(
        SQLEnum(Role, native_enum=False, length=20, validate_strings=True),
        nullable=False,
        default=Role.VISITOR,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    items: Mapped[list["Item"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan", passive_deletes=True
    )

    @property
    def permissions(self) -> frozenset[Permission]:
        """Return the permissions granted by this user's role."""
        return permissions_for(self.role)

    def __repr__(self) -> str:
        """Return an unambiguous representation for logs."""
        return f"<User id={self.id} username={self.username!r} role={self.role.value}>"
