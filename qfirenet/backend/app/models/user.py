"""
models/user.py — SQLAlchemy ORM model for the User table.

This model stores registered user accounts.  Passwords are NEVER stored
in plain text — only the bcrypt hash (see auth/utils.py for hashing logic).

Relationship to ScanResult:
  One User can have many ScanResults (one-to-many).
  ScanResult.user_id is a foreign key pointing to users.id.
  Anonymous scans set user_id = NULL.
"""

from datetime import datetime

from sqlalchemy import Integer, String, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.database import Base


class User(Base):
    """
    Represents a registered QFireNet user account.

    Columns:
      id              — Auto-incremented integer primary key.
      email           — Unique email address used to log in.
      hashed_password — bcrypt hash of the user's password (NEVER plain text).
      created_at      — Timestamp when the account was created (auto-filled by DB).
    """

    __tablename__ = "users"

    # Primary key — SQLAlchemy auto-increments this via the DB sequence.
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Email must be unique — it acts as the username for login.
    # index=True speeds up lookups by email during login.
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)

    # Only the bcrypt hash is stored.  Original password cannot be recovered
    # (bcrypt is a one-way function — we only verify, never decrypt).
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    # Automatically set by the database on INSERT.  We never set this manually.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # ORM relationship: user.scans gives us all ScanResult rows for this user.
    # lazy="dynamic" means SQLAlchemy doesn't load all scans immediately —
    # it builds a query object instead (efficient for large collections).
    scans = relationship("ScanResult", back_populates="user", lazy="dynamic")
