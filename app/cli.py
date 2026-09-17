"""Offline administration commands.

These run directly against the database and need no token, so they work even when
nobody can log in — for example after ``FIRST_SUPERADMIN_PASSWORD`` in ``.env`` was
changed, which does *not* update an account that already exists.

Usage::

    python -m app.cli list-users
    python -m app.cli create-user --username jane --email jane@x.com --role manager
    python -m app.cli set-role --username jane --role admin
    python -m app.cli reset-password --username jane
    python -m app.cli sync-superadmin

Every command that takes a password prompts for it when the flag is omitted, so
credentials never end up in the shell history.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from collections.abc import Sequence

from pydantic import ValidationError as PydanticValidationError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import PrivateAPIError, ValidationError
from app.core.logger import get_logger
from app.core.rbac import Role, permissions_for
from app.core.security import hash_password
from app.crud import user as user_crud
from app.db.init_db import create_tables
from app.db.session import SessionLocal
from app.schemas.user import UserCreate

logger = get_logger(__name__)

ROLE_CHOICES: list[str] = [role.value for role in Role]


def _prompt_password(confirm: bool = True) -> str:
    """Ask for a password on the terminal without echoing it.

    Args:
        confirm: Ask twice and require both entries to match.

    Returns:
        The password that was entered.

    Raises:
        ValidationError: If the two entries differ, or nothing was entered.
    """
    password = getpass.getpass("Password: ")
    if not password:
        raise ValidationError("No password was entered.")
    if confirm and password != getpass.getpass("Confirm password: "):
        raise ValidationError("The two passwords do not match.")
    return password


def _print_user(user: object, prefix: str = "") -> None:
    """Print a one-line summary of a user account.

    Args:
        user: A ``User`` ORM instance.
        prefix: Optional text printed before the summary.
    """
    status = "active" if getattr(user, "is_active") else "inactive"
    print(
        f"{prefix}id={getattr(user, 'id')} "
        f"username={getattr(user, 'username')} "
        f"email={getattr(user, 'email')} "
        f"role={getattr(user, 'role').value} "
        f"[{status}]"
    )


def cmd_list_users(args: argparse.Namespace, session: Session) -> int:
    """List every account with its role and permissions.

    Args:
        args: Parsed command line arguments.
        session: Active database session.

    Returns:
        Process exit code.
    """
    users, total = user_crud.list_users(session, skip=0, limit=200)
    if not users:
        print("No users exist yet. Create one with: python -m app.cli create-user")
        return 0
    print(f"{total} user(s):")
    for user in users:
        _print_user(user, prefix="  ")
        if args.verbose:
            granted = ", ".join(sorted(perm.value for perm in permissions_for(user.role)))
            print(f"      permissions: {granted}")
    return 0


def cmd_create_user(args: argparse.Namespace, session: Session) -> int:
    """Create a new account with the requested role.

    Args:
        args: Parsed command line arguments.
        session: Active database session.

    Returns:
        Process exit code.
    """
    password = args.password or _prompt_password()
    # Validate through the same schema the HTTP endpoint uses, so the CLI cannot
    # create an account the API would have rejected.
    payload = UserCreate(
        username=args.username,
        email=args.email,
        full_name=args.full_name,
        password=password,
        role=Role(args.role),
        is_active=not args.inactive,
    )
    user = user_crud.create_user(session, payload)
    _print_user(user, prefix="Created: ")
    return 0


def cmd_set_role(args: argparse.Namespace, session: Session) -> int:
    """Change the role of an existing account.

    Args:
        args: Parsed command line arguments.
        session: Active database session.

    Returns:
        Process exit code.

    Raises:
        ValidationError: If the account does not exist.
    """
    user = user_crud.get_by_identifier(session, args.username)
    if user is None:
        raise ValidationError(f"No user matches '{args.username}'.")

    previous = user.role.value
    user.role = Role(args.role)
    if args.activate:
        user.is_active = True
    if args.deactivate:
        user.is_active = False
    session.commit()
    session.refresh(user)

    _print_user(user, prefix=f"Updated (was role={previous}): ")
    logger.info("CLI changed user id=%s role %s -> %s", user.id, previous, user.role.value)
    return 0


def cmd_reset_password(args: argparse.Namespace, session: Session) -> int:
    """Set a new password for an existing account.

    Args:
        args: Parsed command line arguments.
        session: Active database session.

    Returns:
        Process exit code.

    Raises:
        ValidationError: If the account does not exist.
    """
    user = user_crud.get_by_identifier(session, args.username)
    if user is None:
        raise ValidationError(f"No user matches '{args.username}'.")

    password = args.password or _prompt_password()
    user_crud.set_password(session, user, password)
    _print_user(user, prefix="Password reset for: ")
    logger.info("CLI reset the password for user id=%s", user.id)
    return 0


def cmd_sync_superadmin(args: argparse.Namespace, session: Session) -> int:
    """Align the superadmin account with the current ``.env`` values.

    Editing ``FIRST_SUPERADMIN_*`` never touches an account that already exists,
    which is the usual reason a superadmin can no longer log in. This command
    applies the configured e-mail and password to the existing account, or creates
    it when none exists.

    Args:
        args: Parsed command line arguments.
        session: Active database session.

    Returns:
        Process exit code.
    """
    username = settings.first_superadmin_username
    user = user_crud.get_by_identifier(session, username)

    if user is None:
        payload = UserCreate(
            username=username,
            email=settings.first_superadmin_email,
            full_name="Platform Superadmin",
            password=settings.first_superadmin_password,
            role=Role.SUPERADMIN,
            is_active=True,
        )
        created = user_crud.create_user(session, payload)
        _print_user(created, prefix="Created superadmin from .env: ")
        return 0

    conflict = user_crud.get_by_email(session, settings.first_superadmin_email)
    if conflict is not None and conflict.id != user.id:
        raise ValidationError(
            f"E-mail '{settings.first_superadmin_email}' already belongs to user "
            f"id={conflict.id}. Change FIRST_SUPERADMIN_EMAIL or free that address."
        )

    user.email = settings.first_superadmin_email
    user.hashed_password = hash_password(settings.first_superadmin_password)
    user.role = Role.SUPERADMIN
    user.is_active = True
    session.commit()
    session.refresh(user)

    _print_user(user, prefix="Synchronised with .env: ")
    print("You can now log in with FIRST_SUPERADMIN_PASSWORD from your .env file.")
    logger.warning("CLI synchronised the superadmin account id=%s with .env values.", user.id)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the command line parser.

    Returns:
        The configured parser.
    """
    parser = argparse.ArgumentParser(
        prog="python -m app.cli",
        description="Offline administration for the Private API (no token required).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list-users", help="List every account.")
    list_parser.add_argument(
        "-v", "--verbose", action="store_true", help="Also print each role's permissions."
    )
    list_parser.set_defaults(handler=cmd_list_users)

    create_parser = subparsers.add_parser("create-user", help="Create an account.")
    create_parser.add_argument("--username", required=True, help="3-50 chars, unique.")
    create_parser.add_argument("--email", required=True, help="Unique e-mail address.")
    create_parser.add_argument("--full-name", default=None, help="Optional display name.")
    create_parser.add_argument(
        "--password",
        default=None,
        help="8-72 chars with at least one letter and one digit. Prompted for if omitted.",
    )
    create_parser.add_argument(
        "--role", default=Role.VISITOR.value, choices=ROLE_CHOICES, help="Role to assign."
    )
    create_parser.add_argument(
        "--inactive", action="store_true", help="Create the account deactivated."
    )
    create_parser.set_defaults(handler=cmd_create_user)

    role_parser = subparsers.add_parser("set-role", help="Change an account's role.")
    role_parser.add_argument("--username", required=True, help="Username or e-mail address.")
    role_parser.add_argument("--role", required=True, choices=ROLE_CHOICES, help="New role.")
    role_parser.add_argument("--activate", action="store_true", help="Also activate the account.")
    role_parser.add_argument(
        "--deactivate", action="store_true", help="Also deactivate the account."
    )
    role_parser.set_defaults(handler=cmd_set_role)

    password_parser = subparsers.add_parser("reset-password", help="Set a new password.")
    password_parser.add_argument("--username", required=True, help="Username or e-mail address.")
    password_parser.add_argument(
        "--password", default=None, help="New password. Prompted for if omitted."
    )
    password_parser.set_defaults(handler=cmd_reset_password)

    sync_parser = subparsers.add_parser(
        "sync-superadmin",
        help="Apply the FIRST_SUPERADMIN_* values from .env to the superadmin account.",
    )
    sync_parser.set_defaults(handler=cmd_sync_superadmin)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one CLI command.

    Args:
        argv: Argument list, defaulting to ``sys.argv[1:]``.

    Returns:
        Process exit code: ``0`` on success, ``1`` on a handled failure.
    """
    args = build_parser().parse_args(argv)
    create_tables()

    session = SessionLocal()
    try:
        return int(args.handler(args, session))
    except PrivateAPIError as exc:
        print(f"Error: {exc.message}", file=sys.stderr)
        return 1
    except PydanticValidationError as exc:
        # Report the username/e-mail/password rules one line per offending field,
        # rather than dumping Pydantic's full multi-line representation.
        for error in exc.errors():
            field = ".".join(str(part) for part in error["loc"])
            message = error["msg"].removeprefix("Value error, ")
            print(f"Error: {field}: {message}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 1
    finally:
        session.close()


if __name__ == "__main__":
    sys.exit(main())
