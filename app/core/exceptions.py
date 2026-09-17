"""Project-wide exception hierarchy.

Every exception raised deliberately by application code inherits from
:class:`PrivateAPIError`, which carries an HTTP status code and a message so the
API layer can translate any domain error into a consistent JSON response.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Any


class PrivateAPIError(Exception):
    """Base class for all application errors.

    Attributes:
        message: Human readable description of the failure.
        status_code: HTTP status code used when the error reaches the API layer.
        details: Optional structured context about the failure.
    """

    status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR
    default_message: str = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict[str, Any] | None = None,
        status_code: int | None = None,
    ) -> None:
        """Initialise the error.

        Args:
            message: Overrides ``default_message`` when provided.
            details: Optional structured context added to the API response.
            status_code: Overrides the class level status code when provided.
        """
        self.message = message or self.default_message
        self.details = details or {}
        if status_code is not None:
            self.status_code = status_code
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON serialisable representation of the error."""
        payload: dict[str, Any] = {"error": type(self).__name__, "detail": self.message}
        if self.details:
            payload["details"] = self.details
        return payload


class ConfigurationError(PrivateAPIError):
    """Raised when required configuration is missing or invalid."""

    status_code = HTTPStatus.INTERNAL_SERVER_ERROR
    default_message = "Invalid application configuration."


class ValidationError(PrivateAPIError):
    """Raised when input data fails a business rule."""

    status_code = HTTPStatus.UNPROCESSABLE_ENTITY
    default_message = "The submitted data is invalid."


class AuthenticationError(PrivateAPIError):
    """Raised when a caller cannot be identified."""

    status_code = HTTPStatus.UNAUTHORIZED
    default_message = "Could not validate credentials."


class TokenError(AuthenticationError):
    """Raised when a JWT is malformed, expired, revoked or of the wrong type."""

    default_message = "The provided token is invalid or has expired."


class AuthorizationError(PrivateAPIError):
    """Raised when an authenticated caller lacks the required permission."""

    status_code = HTTPStatus.FORBIDDEN
    default_message = "You do not have permission to perform this action."


class NotFoundError(PrivateAPIError):
    """Raised when a requested resource does not exist."""

    status_code = HTTPStatus.NOT_FOUND
    default_message = "The requested resource was not found."


class ConflictError(PrivateAPIError):
    """Raised when a resource violates a uniqueness constraint."""

    status_code = HTTPStatus.CONFLICT
    default_message = "The resource conflicts with an existing record."


class DatabaseError(PrivateAPIError):
    """Raised when a database operation fails unexpectedly."""

    status_code = HTTPStatus.INTERNAL_SERVER_ERROR
    default_message = "A database error occurred."
