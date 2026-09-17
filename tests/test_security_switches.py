"""Verification of the AUTHENTICATION_ENABLED / AUTHORIZATION_ENABLED switches.

Run with::

    python -m tests.test_security_switches

`Settings` is cached per process and read at import time, so each of the four
switch combinations is exercised in its own subprocess. The parent process runs
the combinations; the child process runs one scenario and reports its result.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Final

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
PREFIX: Final[str] = "/api/v1"
SUPERADMIN_PASSWORD: Final[str] = "SuperSecret123"
VISITOR_PASSWORD: Final[str] = "VisitorPass123"

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


def _child_env(authentication: bool, authorization: bool, db_path: Path) -> dict[str, str]:
    """Build the environment for one scenario subprocess.

    Args:
        authentication: Value for ``AUTHENTICATION_ENABLED``.
        authorization: Value for ``AUTHORIZATION_ENABLED``.
        db_path: SQLite file the scenario should use.

    Returns:
        A complete environment mapping for the child process.
    """
    env = dict(os.environ)
    env.update(
        {
            "DATABASE_URL": f"sqlite:///{db_path.as_posix()}",
            "JWT_SECRET_KEY": "switch-test-access-secret-key-that-is-long-enough-0000",
            "JWT_REFRESH_SECRET_KEY": "switch-test-refresh-secret-key-that-is-long-enough-00",
            "FIRST_SUPERADMIN_USERNAME": "superadmin",
            "FIRST_SUPERADMIN_EMAIL": "superadmin@example.com",
            "FIRST_SUPERADMIN_PASSWORD": SUPERADMIN_PASSWORD,
            "AUTH_BYPASS_USERNAME": "superadmin",
            "AUTHENTICATION_ENABLED": str(authentication).lower(),
            "AUTHORIZATION_ENABLED": str(authorization).lower(),
            "LOG_LEVEL": "CRITICAL",
            "PYTHONPATH": str(PROJECT_ROOT),
        }
    )
    return env


def run_scenario(authentication: bool, authorization: bool) -> dict[str, Any]:
    """Run one switch combination in a subprocess and return its probe results.

    Args:
        authentication: Value for ``AUTHENTICATION_ENABLED``.
        authorization: Value for ``AUTHORIZATION_ENABLED``.

    Returns:
        A mapping of probe name to observed HTTP status (or reported value).

    Raises:
        RuntimeError: If the child process failed to produce a result.
    """
    db_path = Path(tempfile.gettempdir()) / (
        f"private_api_switches_{int(authentication)}{int(authorization)}.db"
    )
    for suffix in ("", "-wal", "-shm"):
        Path(str(db_path) + suffix).unlink(missing_ok=True)

    completed = subprocess.run(
        [sys.executable, "-m", "tests.test_security_switches", "--child"],
        cwd=PROJECT_ROOT,
        env=_child_env(authentication, authorization, db_path),
        capture_output=True,
        text=True,
        timeout=180,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"Scenario subprocess failed:\n{completed.stdout}\n{completed.stderr}")

    for line in reversed(completed.stdout.splitlines()):
        if line.startswith("RESULT "):
            return json.loads(line.removeprefix("RESULT "))
    raise RuntimeError(f"Scenario produced no result:\n{completed.stdout}\n{completed.stderr}")


def child_main() -> None:
    """Probe the running configuration and print a JSON result line."""
    from fastapi.testclient import TestClient

    from app.core.config import settings
    from app.main import app

    results: dict[str, Any] = {
        "authentication_enabled": settings.authentication_enabled,
        "authorization_enabled": settings.authorization_enabled,
    }

    with TestClient(app) as client:
        health = client.get("/health").json()
        results["health_authentication"] = health["authentication"]
        results["health_authorization"] = health["authorization"]

        # No Authorization header at all.
        results["anonymous_list_items"] = client.get(f"{PREFIX}/items").status_code
        results["anonymous_create_item"] = client.post(
            f"{PREFIX}/items", json={"name": "anonymous item", "quantity": 1, "price": 1.0}
        ).status_code
        results["anonymous_me"] = client.get(f"{PREFIX}/auth/me").status_code
        results["garbage_token_list"] = client.get(
            f"{PREFIX}/items", headers={"Authorization": "Bearer not-a-jwt"}
        ).status_code

        # A visitor holds `read` only; used to probe the authorization switch.
        login = client.post(
            f"{PREFIX}/auth/login",
            data={"username": "superadmin", "password": SUPERADMIN_PASSWORD},
        )
        results["superadmin_login"] = login.status_code
        if login.status_code == 200:
            super_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            created = client.post(
                f"{PREFIX}/users",
                headers=super_headers,
                json={
                    "username": "visitor",
                    "email": "visitor@example.com",
                    "password": VISITOR_PASSWORD,
                    "role": "visitor",
                },
            )
            results["register_visitor"] = created.status_code

            visitor_login = client.post(
                f"{PREFIX}/auth/login",
                data={"username": "visitor", "password": VISITOR_PASSWORD},
            )
            if visitor_login.status_code == 200:
                visitor_headers = {
                    "Authorization": f"Bearer {visitor_login.json()['access_token']}"
                }
                results["visitor_read"] = client.get(
                    f"{PREFIX}/items", headers=visitor_headers
                ).status_code
                results["visitor_create"] = client.post(
                    f"{PREFIX}/items",
                    headers=visitor_headers,
                    json={"name": "visitor item", "quantity": 1, "price": 1.0},
                ).status_code
                results["visitor_register_user"] = client.post(
                    f"{PREFIX}/users",
                    headers=visitor_headers,
                    json={
                        "username": "sneaky",
                        "email": "sneaky@example.com",
                        "password": "Sneaky12345",
                        "role": "admin",
                    },
                ).status_code

    from app.db.session import engine

    engine.dispose()
    print("RESULT " + json.dumps(results))


def run() -> int:
    """Execute all four switch combinations.

    Returns:
        ``0`` when every assertion passed, ``1`` otherwise.
    """
    print("\n[A] Defaults: both switches enabled (authentication + authorization)")
    both = run_scenario(True, True)
    check(both["authentication_enabled"] is True, "AUTHENTICATION_ENABLED defaults to true")
    check(both["authorization_enabled"] is True, "AUTHORIZATION_ENABLED defaults to true")
    check(both["health_authentication"] == "enabled", "/health reports authentication enabled")
    check(both["health_authorization"] == "enabled", "/health reports authorization enabled")
    check(both["anonymous_list_items"] == 401, "anonymous GET /items -> 401")
    check(both["anonymous_create_item"] == 401, "anonymous POST /items -> 401")
    check(both["garbage_token_list"] == 401, "invalid token -> 401")
    check(both["visitor_read"] == 200, "visitor may read -> 200")
    check(both["visitor_create"] == 403, "visitor may not write -> 403")
    check(both["visitor_register_user"] == 403, "visitor may not register users -> 403")

    print("\n[B] Authentication disabled, authorization enabled")
    no_auth = run_scenario(False, True)
    check(no_auth["health_authentication"] == "disabled", "/health reports authentication disabled")
    check(no_auth["health_authorization"] == "enabled", "/health still reports authorization on")
    check(no_auth["anonymous_list_items"] == 200, "anonymous GET /items -> 200 (no token needed)")
    check(no_auth["anonymous_create_item"] == 201, "anonymous POST /items -> 201")
    check(no_auth["anonymous_me"] == 200, "anonymous GET /auth/me resolves the bypass identity")
    check(no_auth["garbage_token_list"] == 200, "an invalid token is ignored entirely")

    print("\n[C] Authentication enabled, authorization disabled")
    no_authz = run_scenario(True, False)
    check(no_authz["health_authentication"] == "enabled", "/health reports authentication enabled")
    check(no_authz["health_authorization"] == "disabled", "/health reports authorization disabled")
    check(no_authz["anonymous_list_items"] == 401, "a token is still required -> 401")
    check(no_authz["garbage_token_list"] == 401, "an invalid token is still rejected -> 401")
    check(no_authz["visitor_read"] == 200, "visitor may read -> 200")
    check(no_authz["visitor_create"] == 201, "visitor may now write -> 201 (RBAC bypassed)")
    check(
        no_authz["visitor_register_user"] == 201,
        "visitor may now register users -> 201 (RBAC bypassed)",
    )

    print("\n[D] Both switches disabled")
    neither = run_scenario(False, False)
    check(neither["health_authentication"] == "disabled", "/health reports authentication disabled")
    check(neither["health_authorization"] == "disabled", "/health reports authorization disabled")
    check(neither["anonymous_list_items"] == 200, "anonymous GET /items -> 200")
    check(neither["anonymous_create_item"] == 201, "anonymous POST /items -> 201")

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
    if "--child" in sys.argv:
        child_main()
        sys.exit(0)
    sys.exit(run())
