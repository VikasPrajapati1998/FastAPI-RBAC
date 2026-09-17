"""User request and response schemas."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.core.rbac import Permission, Role, permissions_for


class UserBase(BaseModel):
    """Fields shared by user input schemas."""

    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr
    full_name: str | None = Field(default=None, max_length=150)


class UserCreate(UserBase):
    """Payload accepted when registering a new account (superadmin only)."""

    password: str = Field(min_length=8, max_length=72, description="Plain text password.")
    role: Role = Field(default=Role.VISITOR, description="Role assigned to the new account.")
    is_active: bool = Field(default=True)

    @field_validator("password")
    @classmethod
    def _password_strength(cls, value: str) -> str:
        """Require a mix of letters and digits in every password."""
        if not any(char.isdigit() for char in value) or not any(char.isalpha() for char in value):
            raise ValueError("Password must contain at least one letter and one digit.")
        return value


class UserUpdate(BaseModel):
    """Full replacement payload used by ``PUT /users/{user_id}``."""

    email: EmailStr
    full_name: str | None = Field(default=None, max_length=150)


class UserPatch(BaseModel):
    """Partial payload used by ``PATCH /users/{user_id}``; unset fields are ignored."""

    email: EmailStr | None = None
    full_name: str | None = Field(default=None, max_length=150)
    password: str | None = Field(default=None, min_length=8, max_length=72)


class UserRoleUpdate(BaseModel):
    """Payload for changing a role or the active flag (``role:manage``)."""

    role: Role | None = None
    is_active: bool | None = None


class PasswordChange(BaseModel):
    """Payload allowing a user to rotate their own password."""

    current_password: str = Field(min_length=1, max_length=72)
    new_password: str = Field(min_length=8, max_length=72)

    @field_validator("new_password")
    @classmethod
    def _password_strength(cls, value: str) -> str:
        """Require a mix of letters and digits in every password."""
        if not any(char.isdigit() for char in value) or not any(char.isalpha() for char in value):
            raise ValueError("Password must contain at least one letter and one digit.")
        return value


class UserRead(BaseModel):
    """Public representation of a user account."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: EmailStr
    full_name: str | None
    role: Role
    is_active: bool
    created_at: datetime
    updated_at: datetime


class UserWithPermissions(UserRead):
    """User representation including the effective permission set."""

    permissions: list[Permission]

    @classmethod
    def from_user(cls, user: object) -> "UserWithPermissions":
        """Build the schema from an ORM user, deriving permissions from its role.

        Args:
            user: A ``User`` ORM instance.

        Returns:
            The serialisable representation including the permission set.
        """
        base = UserRead.model_validate(user)
        return cls(**base.model_dump(), permissions=sorted(permissions_for(base.role)))
