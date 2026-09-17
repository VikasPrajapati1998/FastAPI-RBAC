"""SQLAlchemy engine and session management."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.exceptions import ConfigurationError, DatabaseError
from app.core.logger import get_logger

logger = get_logger(__name__)

def _ensure_sqlite_directory() -> None:
    """Create the directory holding the SQLite file, if it does not exist yet.

    SQLite will happily create the database file itself, but not the directory
    above it, so a fresh checkout would otherwise fail with "unable to open
    database file".

    Raises:
        ConfigurationError: If the directory cannot be created.
    """
    sqlite_path = settings.sqlite_path
    if sqlite_path is None:
        return
    try:
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ConfigurationError(
            f"Unable to create the database directory '{sqlite_path.parent}'."
        ) from exc


_ensure_sqlite_directory()

engine: Engine = create_engine(
    settings.resolved_database_url,
    connect_args=settings.sqlalchemy_connect_args,
    echo=settings.debug,
    future=True,
)

SessionLocal: sessionmaker[Session] = sessionmaker(
    bind=engine, autocommit=False, autoflush=False, expire_on_commit=False, class_=Session
)


@event.listens_for(engine, "connect")
def _configure_sqlite(dbapi_connection, _connection_record) -> None:  # type: ignore[no-untyped-def]
    """Enable foreign keys and WAL mode on every new SQLite connection."""
    if not settings.database_url.startswith("sqlite"):
        return
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
    finally:
        cursor.close()


def get_db() -> Generator[Session, None, None]:
    """Yield a database session for the lifetime of one request.

    Yields:
        An open :class:`~sqlalchemy.orm.Session`.

    Raises:
        DatabaseError: If the session has to be rolled back because of a driver error.
    """
    session = SessionLocal()
    try:
        yield session
    except SQLAlchemyError as exc:
        session.rollback()
        logger.exception("Rolling back the session after a database error.")
        raise DatabaseError("The database rejected the requested operation.") from exc
    finally:
        session.close()
