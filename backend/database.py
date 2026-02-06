# ---------------------------------------------------------------------------
# Author  : Kyle <kyle@hacking-linux.com>
# Version : 20260206v1
# ---------------------------------------------------------------------------
"""
SQLAlchemy engine, session factory, declarative base, and the FastAPI
dependency that provides a transactional DB session per request.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from core.config import settings

# pool_pre_ping keeps idle connections alive across MySQL's wait_timeout
engine = create_engine(settings.database_url, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """
    FastAPI dependency.  Yields a session for the duration of the request,
    then closes it.  Use with Depends(get_db).
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
