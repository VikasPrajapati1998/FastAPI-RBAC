"""End-to-end verification of authentication and the RBAC matrix.

Run with::

    python -m tests.test_rbac_flow

The suite uses FastAPI's ``TestClient`` against a throwaway SQLite file, logs in
as every role and asserts that each HTTP method is either allowed or rejected
with ``403`` exactly as the role matrix specifies. It is intentionally
dependency free (no pytest) so it can run in any environment.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Final

_TEMP_DB: Final[Path] = Path(tempfile.gettempdir()) / "private_api_smoketest.db"
_TEMP_DB.unlink(missing_ok=True)

# Configure the application before it is imported, so the test never touches the
# developer's real database or .env values.
os.environ.update(
    {
        "DATABASE_URL": f"sqlite:///{_TEMP_DB.as_posix()}",
        "JWT_SECRET_KEY": "smoke-test-access-secret-key-that-is-long-enough-000000",
        "JWT_REFRESH_SECRET_KEY": "smoke-test-refresh-secret-key-that-is-long-enough-0000",
        "FIRST_SUPERADMIN_USERNAME": "superadmin",
        "FIRST_SUPERADMIN_EMAIL": "superadmin@example.com",
        "FIRST_SUPERADMIN_PASSWORD": "SuperSecret123",
        "LOG_LEVEL": "WARNING",
        "ACCESS_TOKEN_EXPIRE_MINUTES": "5",
    }
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from app.core.rbac import Permission, Role, ROLE_PERMISSIONS  # noqa: E402
from app.main import app  # noqa: E402

PREFIX: Final[str] = "/api/v1"
PASSWORD: Final[str] = "RolePassword123"

_failures: list[str] = []
_checks = 0


def check(condition: bool, label: str) -> None:
    """Record the outcome of a single assertion.

    Args:
        condition: The expression that must be true.
        label: Human readable description of the expectation.
    """
    global _checks
    _checks += 1
    if condition:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}")
        _failures.append(label)


def login(client: TestClient, username: str, password: str) -> dict[str, Any]:
    """Log in and return the token pair payload.

    Args:
        client: The test client.
        username: Username or e-mail address.
        password: Plain text password.

    Returns:
        The decoded token pair response.
    """
    response = client.post(
        f"{PREFIX}/auth/login", data={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return response.json()


def auth_headers(token: str) -> dict[str, str]:
    """Return the bearer authorization header for ``token``."""
    return {"Authorization": f"Bearer {token}"}


def run() -> int:
    """Execute the whole scenario.

    Returns:
        ``0`` when every assertion passed, ``1`` otherwise.
    """
    with TestClient(app) as client:
        print("\n[1] Health and unauthenticated access")
        check(client.get("/health").json()["status"] == "ok", "GET /health reports ok")
        check(client.get(f"{PREFIX}/items").status_code == 401, "items require a token")
        check(
            client.get(f"{PREFIX}/items", headers=auth_headers("not-a-jwt")).status_code == 401,
            "a malformed token is rejected",
        )

        print("\n[2] Superadmin login and token pair")
        tokens = login(client, "superadmin", "SuperSecret123")
        super_headers = auth_headers(tokens["access_token"])
        check(tokens["expires_in"] == 300, "access token expires in 5 minutes (300s)")
        check(bool(tokens["refresh_token"]), "a refresh token is issued")
        me = client.get(f"{PREFIX}/auth/me", headers=super_headers).json()
        check(me["role"] == "superadmin", "GET /auth/me identifies the superadmin")
        check(
            set(me["permissions"]) == {perm.value for perm in Permission},
            "superadmin holds every permission",
        )

        print("\n[3] Superadmin registers one account per role")
        created: dict[Role, int] = {}
        for role in (Role.ADMIN, Role.MANAGER, Role.SUPERVISOR, Role.VISITOR):
            response = client.post(
                f"{PREFIX}/users",
                headers=super_headers,
                json={
                    "username": role.value,
                    "email": f"{role.value}@example.com",
                    "full_name": role.value.title(),
                    "password": PASSWORD,
                    "role": role.value,
                },
            )
            check(response.status_code == 201, f"registered the {role.value} account")
            if response.status_code == 201:
                body = response.json()
                created[role] = body["id"]
                expected = {perm.value for perm in ROLE_PERMISSIONS[role]}
                check(
                    set(body["permissions"]) == expected,
                    f"{role.value} permissions are {sorted(expected)}",
                )

        duplicate = client.post(
            f"{PREFIX}/users",
            headers=super_headers,
            json={
                "username": "admin",
                "email": "other@example.com",
                "password": PASSWORD,
                "role": "visitor",
            },
        )
        check(duplicate.status_code == 409, "a duplicate username is rejected with 409")

        print("\n[4] Every role logs in")
        headers: dict[Role, dict[str, str]] = {Role.SUPERADMIN: super_headers}
        refresh_tokens: dict[Role, str] = {Role.SUPERADMIN: tokens["refresh_token"]}
        for role in created:
            pair = login(client, role.value, PASSWORD)
            headers[role] = auth_headers(pair["access_token"])
            refresh_tokens[role] = pair["refresh_token"]
            check(True, f"{role.value} logged in")

        print("\n[5] Registration is restricted to the superadmin")
        for role in (Role.ADMIN, Role.MANAGER, Role.SUPERVISOR, Role.VISITOR):
            response = client.post(
                f"{PREFIX}/users",
                headers=headers[role],
                json={
                    "username": f"new-{role.value}",
                    "email": f"new-{role.value}@example.com",
                    "password": PASSWORD,
                    "role": "visitor",
                },
            )
            check(response.status_code == 403, f"{role.value} cannot register a user (403)")

        print("\n[6] Item CRUD against the role matrix")
        item_ids: dict[Role, int] = {}

        for role in (Role.SUPERADMIN, Role.ADMIN, Role.MANAGER, Role.SUPERVISOR, Role.VISITOR):
            allowed_write = Permission.WRITE in ROLE_PERMISSIONS[role]
            response = client.post(
                f"{PREFIX}/items",
                headers=headers[role],
                json={
                    "name": f"{role.value} widget",
                    "description": "created by the smoke test",
                    "quantity": 3,
                    "price": 19.99,
                },
            )
            expected = 201 if allowed_write else 403
            check(
                response.status_code == expected,
                f"POST /items as {role.value} -> {expected}",
            )
            if response.status_code == 201:
                item_ids[role] = response.json()["id"]

        seed_item = item_ids[Role.SUPERADMIN]

        for role in (Role.SUPERADMIN, Role.ADMIN, Role.MANAGER, Role.SUPERVISOR, Role.VISITOR):
            perms = ROLE_PERMISSIONS[role]
            role_headers = headers[role]

            check(
                client.get(f"{PREFIX}/items", headers=role_headers).status_code == 200,
                f"GET /items as {role.value} -> 200",
            )
            check(
                client.get(f"{PREFIX}/items/{seed_item}", headers=role_headers).status_code == 200,
                f"GET /items/{{id}} as {role.value} -> 200",
            )
            check(
                client.head(f"{PREFIX}/items/{seed_item}", headers=role_headers).status_code == 204,
                f"HEAD /items/{{id}} as {role.value} -> 204",
            )

            expected = 200 if Permission.UPDATE in perms else 403
            put = client.put(
                f"{PREFIX}/items/{seed_item}",
                headers=role_headers,
                json={
                    "name": f"replaced by {role.value}",
                    "description": None,
                    "quantity": 5,
                    "price": 5.5,
                    "is_active": True,
                },
            )
            check(put.status_code == expected, f"PUT /items/{{id}} as {role.value} -> {expected}")

            patch = client.patch(
                f"{PREFIX}/items/{seed_item}",
                headers=role_headers,
                json={"quantity": 7},
            )
            check(
                patch.status_code == expected, f"PATCH /items/{{id}} as {role.value} -> {expected}"
            )

            options = client.options(f"{PREFIX}/items", headers=role_headers)
            check(options.status_code == 204, f"OPTIONS /items as {role.value} -> 204")
            allow = options.headers.get("Allow", "")
            check(
                ("DELETE" in allow) is (Permission.DELETE in perms),
                f"Allow header for {role.value} reflects delete access",
            )

        print("\n[7] Deletion is limited to superadmin and admin")
        for role in (Role.MANAGER, Role.SUPERVISOR, Role.VISITOR):
            response = client.delete(f"{PREFIX}/items/{seed_item}", headers=headers[role])
            check(response.status_code == 403, f"DELETE /items/{{id}} as {role.value} -> 403")
        check(
            client.delete(f"{PREFIX}/items/{item_ids[Role.MANAGER]}", headers=headers[Role.ADMIN]).status_code
            == 204,
            "DELETE /items/{id} as admin -> 204",
        )
        check(
            client.delete(f"{PREFIX}/items/{seed_item}", headers=super_headers).status_code == 204,
            "DELETE /items/{id} as superadmin -> 204",
        )
        check(
            client.get(f"{PREFIX}/items/{seed_item}", headers=super_headers).status_code == 404,
            "the deleted item is gone (404)",
        )

        print("\n[8] Role management and privilege escalation guards")
        check(
            client.patch(
                f"{PREFIX}/users/{created[Role.VISITOR]}/access",
                headers=headers[Role.MANAGER],
                json={"role": "admin"},
            ).status_code
            == 403,
            "manager cannot change roles (403)",
        )
        check(
            client.patch(
                f"{PREFIX}/users/{created[Role.VISITOR]}/access",
                headers=headers[Role.ADMIN],
                json={"role": "superadmin"},
            ).status_code
            == 403,
            "admin cannot promote anybody to superadmin (403)",
        )
        promoted = client.patch(
            f"{PREFIX}/users/{created[Role.VISITOR]}/access",
            headers=headers[Role.ADMIN],
            json={"role": "manager"},
        )
        check(promoted.status_code == 200, "admin can promote a visitor to manager")
        check(
            promoted.status_code == 200 and promoted.json()["role"] == "manager",
            "the promoted account now reports the manager role",
        )
        check(
            client.patch(
                f"{PREFIX}/users/{created[Role.ADMIN]}/access",
                headers=headers[Role.ADMIN],
                json={"is_active": False},
            ).status_code
            == 422,
            "an admin cannot change their own access level (422)",
        )
        check(
            client.delete(f"{PREFIX}/users/1", headers=super_headers).status_code == 422,
            "a caller cannot delete their own account (422)",
        )
        check(
            client.delete(f"{PREFIX}/users/1", headers=headers[Role.ADMIN]).status_code == 403,
            "an admin cannot delete the superadmin (403)",
        )

        print("\n[9] Stale claims are rejected after a role change")
        stale = client.get(f"{PREFIX}/items", headers=headers[Role.VISITOR])
        check(stale.status_code == 401, "the promoted user's old token is refused (401)")

        print("\n[10] Refresh rotation and logout")
        refreshed = client.post(
            f"{PREFIX}/auth/refresh", json={"refresh_token": refresh_tokens[Role.MANAGER]}
        )
        check(refreshed.status_code == 200, "a valid refresh token yields a new pair")
        reused = client.post(
            f"{PREFIX}/auth/refresh", json={"refresh_token": refresh_tokens[Role.MANAGER]}
        )
        check(reused.status_code == 401, "a refresh token cannot be reused (401)")

        new_pair = refreshed.json()
        manager_headers = auth_headers(new_pair["access_token"])
        check(
            client.get(f"{PREFIX}/items", headers=manager_headers).status_code == 200,
            "the rotated access token works",
        )
        logout = client.post(
            f"{PREFIX}/auth/logout",
            headers=manager_headers,
            json={"refresh_token": new_pair["refresh_token"]},
        )
        check(logout.status_code == 200, "logout succeeds")
        check(
            client.post(
                f"{PREFIX}/auth/refresh", json={"refresh_token": new_pair["refresh_token"]}
            ).status_code
            == 401,
            "the revoked refresh token is refused (401)",
        )

        print("\n[11] Deactivated accounts lose access")
        check(
            client.patch(
                f"{PREFIX}/users/{created[Role.SUPERVISOR]}/access",
                headers=super_headers,
                json={"is_active": False},
            ).status_code
            == 200,
            "superadmin deactivates the supervisor",
        )
        check(
            client.get(f"{PREFIX}/items", headers=headers[Role.SUPERVISOR]).status_code == 401,
            "the deactivated supervisor is refused (401)",
        )
        check(
            client.post(
                f"{PREFIX}/auth/login", data={"username": "supervisor", "password": PASSWORD}
            ).status_code
            == 401,
            "the deactivated supervisor cannot log in (401)",
        )

        print("\n[12] Self-service password change")
        change = client.patch(
            f"{PREFIX}/auth/me/password",
            headers=headers[Role.ADMIN],
            json={"current_password": PASSWORD, "new_password": "BrandNewPass456"},
        )
        check(change.status_code == 200, "the admin changes their own password")
        check(
            client.post(
                f"{PREFIX}/auth/login", data={"username": "admin", "password": PASSWORD}
            ).status_code
            == 401,
            "the old password no longer works (401)",
        )
        check(
            client.post(
                f"{PREFIX}/auth/login", data={"username": "admin", "password": "BrandNewPass456"}
            ).status_code
            == 200,
            "the new password works",
        )

    print("\n" + "-" * 70)
    print(f"{_checks - len(_failures)}/{_checks} checks passed")
    if _failures:
        print("\nFailed checks:")
        for failure in _failures:
            print(f"  - {failure}")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    exit_code = run()
    # Release the SQLite file handles before removing the throwaway database.
    from app.db.session import engine

    engine.dispose()
    _TEMP_DB.unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(str(_TEMP_DB) + suffix).unlink(missing_ok=True)
    sys.exit(exit_code)
