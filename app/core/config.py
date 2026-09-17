"""Application configuration loaded from the environment.

Settings are read once from environment variables and an optional ``.env`` file.
Secrets are never hardcoded: the JWT keys and the bootstrap superadmin password
must be supplied through the environment.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, ValidationError as PydanticValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.exceptions import ConfigurationError

BASE_DIR: Path = Path(__file__).resolve().parents[2]

SQLITE_FILE_PREFIX: str = "sqlite:///"
"""URL prefix identifying a file-backed SQLite database."""


class Settings(BaseSettings):
    """Strongly typed container for every runtime setting."""

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application -------------------------------------------------------
    app_name: str = "Private API"
    app_version: str = "1.0.0"
    api_v1_prefix: str = "/api/v1"
    debug: bool = False

    # --- Security switches -------------------------------------------------
    authentication_enabled: bool = Field(
        default=True,
        description=(
            "When false, endpoints stop requiring a bearer token and every request "
            "is attributed to `auth_bypass_username`. Development aid only."
        ),
    )
    authorization_enabled: bool = Field(
        default=True,
        description=(
            "When false, RBAC permission checks always pass. Authentication (if "
            "enabled) still applies. Development aid only."
        ),
    )
    auth_bypass_username: str = Field(
        default="superadmin",
        description="Account requests are attributed to while authentication is disabled.",
    )

    # --- JWT ---------------------------------------------------------------
    jwt_secret_key: str = Field(min_length=32)
    jwt_refresh_secret_key: str = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "private-api"
    jwt_audience: str = "private-api-clients"
    access_token_expire_minutes: int = Field(default=5, ge=1)
    refresh_token_expire_minutes: int = Field(default=1440, ge=1)

    # --- Database ----------------------------------------------------------
    database_url: str = "sqlite:///./database/private_api.db"

    # --- Logging -----------------------------------------------------------
    log_level: str = "INFO"
    log_dir: Path = Path("logs")

    # --- Bootstrap superadmin ---------------------------------------------
    first_superadmin_username: str = "superadmin"
    first_superadmin_email: str = "superadmin@example.com"
    first_superadmin_password: str = Field(min_length=8)

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        """Normalise and validate the configured log level."""
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        normalised = value.upper()
        if normalised not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}")
        return normalised

    @field_validator("log_dir")
    @classmethod
    def _absolute_log_dir(cls, value: Path) -> Path:
        """Resolve the log directory relative to the project root."""
        return value if value.is_absolute() else BASE_DIR / value

    @property
    def security_warnings(self) -> list[str]:
        """Return a warning for each disabled security control.

        Returns:
            One message per relaxed control; empty when the API is fully secured.
        """
        warnings: list[str] = []
        if not self.authentication_enabled:
            warnings.append(
                "AUTHENTICATION IS DISABLED: every request is served as "
                f"'{self.auth_bypass_username}' without a token."
            )
        if not self.authorization_enabled:
            warnings.append("AUTHORIZATION IS DISABLED: every RBAC permission check passes.")
        return warnings

    @property
    def sqlite_path(self) -> Path | None:
        """Return the absolute path of the SQLite file, if one is configured.

        Relative paths resolve against the project root rather than the current
        working directory, so the same database is used no matter where the app is
        launched from.

        Returns:
            The absolute file path, or ``None`` for in-memory SQLite and for any
            non-SQLite backend.
        """
        if not self.database_url.startswith(SQLITE_FILE_PREFIX):
            return None
        raw_path = self.database_url[len(SQLITE_FILE_PREFIX) :]
        if not raw_path or raw_path.startswith(":memory:"):
            return None
        path = Path(raw_path)
        return path if path.is_absolute() else (BASE_DIR / path).resolve()

    @property
    def resolved_database_url(self) -> str:
        """Return the database URL the engine should use.

        For file-backed SQLite this is :attr:`database_url` rewritten with an
        absolute path; every other backend is passed through unchanged.

        Returns:
            The URL to hand to ``create_engine``.
        """
        sqlite_path = self.sqlite_path
        if sqlite_path is None:
            return self.database_url
        return f"{SQLITE_FILE_PREFIX}{sqlite_path.as_posix()}"

    @property
    def sqlalchemy_connect_args(self) -> dict[str, Any]:
        """Return engine connect arguments required by the configured driver."""
        if self.database_url.startswith("sqlite"):
            return {"check_same_thread": False}
        return {}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached settings instance.

    Returns:
        The validated :class:`Settings` instance for this process.

    Raises:
        ConfigurationError: If required settings are missing or invalid.
    """
    try:
        return Settings()  # type: ignore[call-arg]
    except PydanticValidationError as exc:
        missing = ", ".join(".".join(str(part) for part in error["loc"]) for error in exc.errors())
        raise ConfigurationError(
            "Configuration is incomplete or invalid. Copy .env.example to .env and "
            f"provide valid values for: {missing}",
        ) from exc


settings: Settings = get_settings()
