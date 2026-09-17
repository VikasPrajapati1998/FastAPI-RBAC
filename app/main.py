"""FastAPI application factory, exception handlers and lifespan wiring."""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.exceptions import AuthenticationError, PrivateAPIError
from app.core.logger import get_log_file, get_logger
from app.core.rbac import ROLE_PERMISSIONS
from app.db.init_db import init_db
from app.db.session import SessionLocal
from app.schemas.common import HealthStatus

logger = get_logger(__name__)

DESCRIPTION = """
A private API secured with JWT bearer tokens and Role Based Access Control.

**Authentication** — `POST /api/v1/auth/login` returns a 5 minute access token plus a
long lived refresh token. Send the access token as `Authorization: Bearer <token>`.
Rotate it through `POST /api/v1/auth/refresh` and end a session with
`POST /api/v1/auth/logout`.

**Authorization** — every endpoint declares the permissions it needs; each role owns a
fixed permission set:

| Role | read | write | update | delete | register users | manage roles |
|------|:----:|:-----:|:------:|:------:|:--------------:|:------------:|
| `superadmin` | yes | yes | yes | yes | yes | yes |
| `admin` | yes | yes | yes | yes | no | yes |
| `manager` | yes | yes | yes | no | no | no |
| `supervisor` | yes | yes | no | no | no | no |
| `visitor` | yes | no | no | no | no | no |
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialise the database on startup; log a clean shutdown.

    Logging is already configured by importing :mod:`app.core.logger`, which
    opens the single log file for this execution.

    Args:
        app: The application instance being started.

    Yields:
        Control back to the server while the application serves requests.
    """
    logger.info("Starting %s v%s (debug=%s)", settings.app_name, settings.app_version, settings.debug)
    logger.info("Writing this run's log to %s", get_log_file())
    init_db()
    logger.info(
        "RBAC ready: %s",
        {role.value: sorted(perm.value for perm in perms) for role, perms in ROLE_PERMISSIONS.items()},
    )
    logger.info(
        "Security switches: authentication=%s authorization=%s",
        "enabled" if settings.authentication_enabled else "DISABLED",
        "enabled" if settings.authorization_enabled else "DISABLED",
    )
    for warning in settings.security_warnings:
        logger.critical("%s Never run this configuration in production.", warning)
    yield
    logger.info("Shutting down %s.", settings.app_name)


def create_app() -> FastAPI:
    """Build and configure the FastAPI application.

    Returns:
        The fully wired application instance.
    """
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=DESCRIPTION,
        debug=settings.debug,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    _register_middleware(app)
    _register_exception_handlers(app)

    app.include_router(api_router, prefix=settings.api_v1_prefix)

    @app.get("/health", response_model=HealthStatus, tags=["System"], summary="Service health")
    def health() -> HealthStatus:
        """Report service and database availability.

        Returns:
            The health payload, with ``database`` set to ``unavailable`` if the
            connectivity probe fails.
        """
        database_state = "ok"
        session = SessionLocal()
        try:
            session.execute(text("SELECT 1"))
        except SQLAlchemyError:
            logger.exception("Health check could not reach the database.")
            database_state = "unavailable"
        finally:
            session.close()
        return HealthStatus(
            status="ok" if database_state == "ok" else "degraded",
            application=settings.app_name,
            version=settings.app_version,
            database=database_state,
            authentication="enabled" if settings.authentication_enabled else "disabled",
            authorization="enabled" if settings.authorization_enabled else "disabled",
        )

    return app


def _register_middleware(app: FastAPI) -> None:
    """Attach the request logging middleware.

    Args:
        app: The application being configured.
    """

    @app.middleware("http")
    async def log_requests(request: Request, call_next):  # type: ignore[no-untyped-def]
        """Tag every request with an id and log its outcome and duration."""
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        started = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-ID"] = request_id
        logger.info(
            "%s %s -> %s | user=%s | %.1fms | request_id=%s",
            request.method,
            request.url.path,
            response.status_code,
            getattr(request.state, "user_id", "anonymous"),
            duration_ms,
            request_id,
        )
        return response


def _register_exception_handlers(app: FastAPI) -> None:
    """Translate domain and framework exceptions into consistent JSON responses.

    Args:
        app: The application being configured.
    """

    @app.exception_handler(PrivateAPIError)
    async def handle_domain_error(request: Request, exc: PrivateAPIError) -> JSONResponse:
        """Render any application error using its own status code."""
        logger.warning(
            "%s on %s %s: %s",
            type(exc).__name__,
            request.method,
            request.url.path,
            exc.message,
        )
        headers = {"WWW-Authenticate": "Bearer"} if isinstance(exc, AuthenticationError) else None
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict(), headers=headers)

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Render request validation failures in the same envelope as domain errors.

        Only the location, message and type of each error are echoed back. Pydantic
        also attaches the offending ``input`` — which is the raw ``bytes`` body when
        the payload is not valid JSON at all, and is not JSON serialisable. Rendering
        it would turn a ``422`` into a ``500``, and would reflect the caller's raw
        payload back at them.
        """
        errors = [
            {
                "field": ".".join(str(part) for part in error.get("loc", ())) or "body",
                "message": str(error.get("msg", "Invalid value.")),
                "type": str(error.get("type", "value_error")),
            }
            for error in exc.errors()
        ]
        logger.info(
            "Validation error on %s %s: %s",
            request.method,
            request.url.path,
            [error["field"] for error in errors],
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "RequestValidationError",
                "detail": "The request payload is invalid.",
                "details": {"errors": errors},
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        """Render framework HTTP errors (404, 405, ...) in the shared envelope."""
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "HTTPException", "detail": exc.detail},
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        """Log an unhandled exception with its traceback and hide the details."""
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": "InternalServerError", "detail": "An unexpected error occurred."},
        )


app = create_app()
