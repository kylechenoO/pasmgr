# ---------------------------------------------------------------------------
# Author  : Kyle <kyle@hacking-linux.com>
# Version : 20260206v1
# ---------------------------------------------------------------------------
"""
Alembic environment – wires the migration engine to the same SQLAlchemy
engine used by the application.

The database URL is loaded from .env via the application's Settings class,
so there is a single source of truth for the connection string.
"""

import sys
import os

# ---------------------------------------------------------------------------
# Path setup – make sure ``backend/`` is importable so that
# ``from core.config import settings`` and model imports work.
# ---------------------------------------------------------------------------
_BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

# Also ensure the project root is on the path so .env is found
_PROJECT_ROOT = os.path.abspath(os.path.join(_BACKEND_DIR, ".."))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from alembic import context
from sqlalchemy import create_engine

from core.config import settings
from database import Base

# Import every ORM model so that Base.metadata knows about all tables.
# Without this, ``alembic revision --autogenerate`` cannot detect them.
import models.user        # noqa: F401, E402
import models.vault_item  # noqa: F401, E402
import models.audit_log   # noqa: F401, E402

# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
connectable = create_engine(settings.database_url)


# ---------------------------------------------------------------------------
# Online mode (the default – uses a live DB connection)
# ---------------------------------------------------------------------------
def run_migrations_online():
    with connectable.connect() as conn:
        context.configure(
            connection=conn,
            target_metadata=Base.metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


# ---------------------------------------------------------------------------
# Offline mode (generates SQL without a live connection)
# ---------------------------------------------------------------------------
def run_migrations_offline():
    context.configure(
        url=settings.database_url,
        target_metadata=Base.metadata,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
