"""
database.py — SQLAlchemy engine creation and session management.

SQLAlchemy works in three layers:
  1. Engine   – the raw connection pool to PostgreSQL.
  2. Session  – a "unit-of-work" wrapper around one or more DB operations.
  3. Base     – the declarative base class that all ORM models inherit from.

FastAPI uses dependency injection to hand each HTTP request its own session,
ensuring sessions are opened per-request and always closed when the request ends.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from app.config import settings


# ── Engine ────────────────────────────────────────────────────────────────────
# create_engine() sets up the connection pool.
# connect_args is needed for SQLite (not used here, but shown for reference).
# For PostgreSQL, psycopg2-binary handles the actual connection under the hood.
engine = create_engine(
    settings.DATABASE_URL,
    # pool_pre_ping=True: Before using a connection from the pool, SQLAlchemy
    # sends a lightweight "ping" to make sure it is still alive.  This prevents
    # "server closed the connection unexpectedly" errors after idle periods.
    pool_pre_ping=True,
)


# ── Session factory ───────────────────────────────────────────────────────────
# SessionLocal is a *class* (a factory).  Every time you call SessionLocal()
# you get a fresh Session object tied to one DB transaction.
# autocommit=False → you must explicitly call session.commit() to save changes.
# autoflush=False  → SQLAlchemy won't automatically flush pending changes before
#                    every query (gives us more control).
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ── Declarative base ──────────────────────────────────────────────────────────
# All ORM model classes (in models/) inherit from Base.
# SQLAlchemy uses this Base to discover tables and generate CREATE TABLE SQL.
class Base(DeclarativeBase):
    pass


# ── FastAPI dependency ────────────────────────────────────────────────────────
def get_db():
    """
    FastAPI dependency that yields a database session for a single request.

    Usage in a router:
        @router.post("/something")
        def my_route(db: Session = Depends(get_db)):
            ...

    The 'yield' turns this into a generator-based dependency:
      - Code before 'yield'  → runs before the route handler (opens session).
      - Code after  'yield'  → runs after the route handler (closes session).
    The try/finally guarantees the session is closed even if an exception occurs.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
