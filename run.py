"""Development entry point: ``python run.py``.

Production deployments should invoke uvicorn (or gunicorn with uvicorn workers)
directly, for example::

    uvicorn app.main:app --host 0.0.0.0 --port 8080 --workers 4
"""

from __future__ import annotations

import uvicorn

from app.core.config import settings
from app.core.logger import get_log_file


def main() -> None:
    """Start the development server using the configured settings."""
    print(f"Logging this run to {get_log_file()}")
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8080,
        reload=settings.debug,
        log_config=None,
    )


if __name__ == "__main__":
    main()

