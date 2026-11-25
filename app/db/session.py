"""OWASP Sentinel - Database Engine and Session Management

Configures connection pooling, SQLite PRAGMA enforcement, and session lifecycle.
"""

import sqlite3
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.base import Base

# Ensure Render, Heroku and cloud postgres URLs work seamlessly with SQLAlchemy
db_url = settings.DATABASE_URL
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg2://", 1)
elif db_url.startswith("postgresql://") and not db_url.startswith("postgresql+"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)

# Configure connection arguments
connect_args = {}
if db_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    db_url,
    connect_args=connect_args,
    echo=False,
)


# SQLite does not enforce foreign keys by default; enable PRAGMA foreign_keys=ON
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a thread-local database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all database tables defined in the metadata and ensure PostgreSQL column definitions."""
    Base.metadata.create_all(bind=engine)
    if "postgres" in db_url:
        try:
            with engine.connect() as conn:
                from sqlalchemy import text
                conn.execute(text("ALTER TABLE finding_category_mappings ALTER COLUMN owasp_category_code TYPE VARCHAR(255);"))
                conn.execute(text("ALTER TABLE finding_category_mappings ALTER COLUMN owasp_edition TYPE VARCHAR(100);"))
                conn.commit()
        except Exception:
            pass
