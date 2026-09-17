"""Role Based Access Control definitions.

Authorization is permission driven: endpoints declare the permissions they need
and each role owns a fixed set of permissions. Adding a role therefore never
requires touching endpoint code.

Role matrix
-----------
==========  ====  =====  ======  ======  =============  ===========
Role        READ  WRITE  UPDATE  DELETE  USER_REGISTER  ROLE_MANAGE
==========  ====  =====  ======  ======  =============  ===========
superadmin  yes   yes    yes     yes     yes            yes
admin       yes   yes    yes     yes     no             yes
manager     yes   yes    yes     no      no             no
supervisor  yes   yes    no      no      no             no
visitor     yes   no     no      no      no             no
==========  ====  =====  ======  ======  =============  ===========
"""

from __future__ import annotations

from enum import StrEnum
from types import MappingProxyType
from typing import Mapping


class Role(StrEnum):
    """Roles a user account can hold."""

    SUPERADMIN = "superadmin"
    ADMIN = "admin"
    MANAGER = "manager"
    SUPERVISOR = "supervisor"
    VISITOR = "visitor"


class Permission(StrEnum):
    """Atomic capabilities that endpoints require."""

    READ = "read"
    """Read any resource (GET / HEAD / OPTIONS)."""

    WRITE = "write"
    """Create new resources (POST)."""

    UPDATE = "update"
    """Modify existing resources (PUT / PATCH)."""

    DELETE = "delete"
    """Remove resources (DELETE)."""

    USER_REGISTER = "user:register"
    """Register brand new user accounts."""

    ROLE_MANAGE = "role:manage"
    """Change the role or the active flag of another account."""


ROLE_PERMISSIONS: Mapping[Role, frozenset[Permission]] = MappingProxyType(
    {
        Role.SUPERADMIN: frozenset(Permission),
        Role.ADMIN: frozenset(
            {
                Permission.READ,
                Permission.WRITE,
                Permission.UPDATE,
                Permission.DELETE,
                Permission.ROLE_MANAGE,
            }
        ),
        Role.MANAGER: frozenset({Permission.READ, Permission.WRITE, Permission.UPDATE}),
        Role.SUPERVISOR: frozenset({Permission.READ, Permission.WRITE}),
        Role.VISITOR: frozenset({Permission.READ}),
    }
)

ROLE_HIERARCHY: Mapping[Role, int] = MappingProxyType(
    {
        Role.SUPERADMIN: 50,
        Role.ADMIN: 40,
        Role.MANAGER: 30,
        Role.SUPERVISOR: 20,
        Role.VISITOR: 10,
    }
)


def permissions_for(role: Role) -> frozenset[Permission]:
    """Return the permission set granted to ``role``.

    Args:
        role: Role to inspect.

    Returns:
        The frozen set of permissions the role holds.
    """
    return ROLE_PERMISSIONS.get(role, frozenset())


def has_permission(role: Role, permission: Permission) -> bool:
    """Report whether ``role`` grants ``permission``.

    Args:
        role: Role to inspect.
        permission: Permission being requested.

    Returns:
        ``True`` when the role holds the permission.
    """
    return permission in permissions_for(role)


def has_all_permissions(role: Role, permissions: frozenset[Permission]) -> bool:
    """Report whether ``role`` grants every permission in ``permissions``.

    Args:
        role: Role to inspect.
        permissions: Permissions that must all be present.

    Returns:
        ``True`` when the role is a superset of the requested permissions.
    """
    return permissions.issubset(permissions_for(role))


def outranks(actor: Role, target: Role) -> bool:
    """Report whether ``actor`` sits strictly above ``target`` in the hierarchy.

    Used to stop a role from modifying or deleting an equal or higher account.

    Args:
        actor: Role of the caller.
        target: Role of the account being acted upon.

    Returns:
        ``True`` when the actor ranks higher than the target.
    """
    return ROLE_HIERARCHY.get(actor, 0) > ROLE_HIERARCHY.get(target, 0)
