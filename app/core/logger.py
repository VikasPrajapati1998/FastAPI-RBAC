"""The single logger for the entire project.

There is exactly one logger (``private_api``) and exactly one log file per
execution. The file is created when this module is first imported and every
module in the project writes to it through :func:`get_logger`::

    logs/
    └── YYYY-MM-DD/
        └── YYYY-MM-DD_HH-MM-SS.log

Modules must never call :func:`logging.basicConfig`, never attach their own
handlers and never open their own files. They do exactly this::

    from app.core.logger import get_logger

    logger = get_logger(__name__)

Handlers are configured once, at import time, so nothing can start a second file
part-way through a run.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Final

from app.core.config import settings
from app.core.exceptions import ConfigurationError

LOGGER_NAME: Final[str] = "private_api"
"""Name of the one and only project logger."""

_LOG_FORMAT: Final[str] = "%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(message)s"
_DATE_FORMAT: Final[str] = "%Y-%m-%d %H:%M:%S"
_UVICORN_LOGGERS: Final[tuple[str, ...]] = ("uvicorn", "uvicorn.error", "uvicorn.access")
_UVICORN_GENERAL_LOGGER: Final[str] = "uvicorn.error"


class UvicornNameFilter(logging.Filter):
    """Stop uvicorn's general logger from reading as an error in the log output.

    Uvicorn routes *all* of its lifecycle messages — "Started server process",
    "Application startup complete", "Uvicorn running on ..." — through a logger
    literally named ``uvicorn.error``, regardless of severity. Because the project
    format string prints the logger name, a perfectly healthy INFO line would read
    as though something had failed.

    This filter relabels those records as plain ``uvicorn`` and keeps the
    ``uvicorn.error`` name only when the record really is an error, so the name and
    the level always agree.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Relabel non-error records from uvicorn's general logger.

        Args:
            record: The record about to be emitted.

        Returns:
            Always ``True`` — the record is renamed, never dropped.
        """
        if record.name == _UVICORN_GENERAL_LOGGER and record.levelno < logging.ERROR:
            record.name = "uvicorn"
        return True


def _create_log_file() -> Path:
    """Create today's log directory and return this execution's log file path.

    Returns:
        Absolute path of the log file for this run.

    Raises:
        ConfigurationError: If the directory or the file cannot be created.
    """
    now = datetime.now()
    day_directory = settings.log_dir / now.strftime("%Y-%m-%d")
    try:
        day_directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigurationError(f"Unable to create log directory '{day_directory}'.") from exc

    log_file = day_directory / f"{now.strftime('%Y-%m-%d_%H-%M-%S')}.log"
    try:
        # Append mode: an existing file from the same second is added to, never truncated.
        log_file.touch(exist_ok=True)
    except OSError as exc:
        raise ConfigurationError(f"Unable to create log file '{log_file}'.") from exc
    return log_file


def _configure() -> tuple[logging.Logger, Path]:
    """Build the project logger and its handlers exactly once.

    Returns:
        A tuple of ``(project_logger, log_file_path)``.

    Raises:
        ConfigurationError: If the log file cannot be opened.
    """
    log_file = _create_log_file()

    project_logger = logging.getLogger(LOGGER_NAME)
    project_logger.setLevel(settings.log_level)
    project_logger.propagate = False
    project_logger.handlers.clear()

    formatter = logging.Formatter(fmt=_LOG_FORMAT, datefmt=_DATE_FORMAT)

    console_handler = logging.StreamHandler(stream=sys.stdout)
    console_handler.setFormatter(formatter)
    project_logger.addHandler(console_handler)

    try:
        file_handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"Unable to open log file '{log_file}'.") from exc
    file_handler.setFormatter(formatter)
    project_logger.addHandler(file_handler)

    # Route the server's own output into the same handlers so one run produces
    # one file containing everything.
    name_filter = UvicornNameFilter()
    for uvicorn_logger_name in _UVICORN_LOGGERS:
        uvicorn_logger = logging.getLogger(uvicorn_logger_name)
        uvicorn_logger.handlers = project_logger.handlers
        uvicorn_logger.setLevel(settings.log_level)
        uvicorn_logger.propagate = False
        uvicorn_logger.addFilter(name_filter)

    project_logger.info("Logging initialised at level %s -> %s", settings.log_level, log_file)
    return project_logger, log_file


logger, LOG_FILE = _configure()
"""The project logger, and the single log file this execution writes to."""


def get_logger(name: str | None = None) -> logging.Logger:
    """Return the project logger, or a named child of it.

    Children share the project logger's handlers, so every module writes to the
    one log file while still reporting its own name in each record.

    Args:
        name: Usually ``__name__``. Omit it to get the project logger itself.

    Returns:
        The configured logger to write through.
    """
    if not name or name == LOGGER_NAME:
        return logger
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


def get_log_file() -> Path:
    """Return the path of the log file this execution is writing to."""
    return LOG_FILE
