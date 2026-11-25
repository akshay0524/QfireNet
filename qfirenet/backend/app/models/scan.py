"""
models/scan.py — SQLAlchemy ORM model for the scan_results table.

This model stores every completed scan — website, email, or APK.
It's a polymorphic table: the 'scan_type' column tells us which kind of scan
produced this row, and 'input_summary' stores a human-readable label for it.

Tables:
  - scan_results : one row per completed scan (all types unified)

Foreign Keys:
  - user_id → users.id (nullable — anonymous scans allowed)

Why JSON for raw_results?
  Storing all signal data as JSON avoids separate tables for each scan type.
  As signals evolve, we add to the JSON blob rather than adding DB columns.
  PostgreSQL's JSONB format gives us efficient storage + query capability.
"""

from datetime import datetime

from sqlalchemy import Integer, Float, String, Text, DateTime, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.database import Base


class ScanResult(Base):
    """
    Represents one completed scan — website, email, or APK.

    Columns:
      id            — Auto-incremented primary key.
      user_id       — FK to users.id; NULL for anonymous scans.
      scan_type     — "website", "email", or "apk".
      input_summary — Human-readable label (URL / email sender / APK filename).
      trust_score   — Computed score 0–100.
      risk_level    — "Low", "Medium", or "High".
      raw_results   — Full JSON blob of all signal outputs.
      explanation   — LLM-generated plain-English explanation.
      scanned_at    — UTC timestamp of when the scan ran.
    """

    __tablename__ = "scan_results"

    # ── Primary key ───────────────────────────────────────────────────────────
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # ── User relationship (optional — anonymous scans have NULL) ──────────────
    # ondelete="SET NULL" means if the user is deleted, their scans remain
    # but user_id is set to NULL (we don't cascade-delete scan history).
    user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ── Scan type discriminator ───────────────────────────────────────────────
    # One of: "website" | "email" | "apk"
    # Indexed because history queries filter by scan_type frequently.
    scan_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)

    # ── Input summary ─────────────────────────────────────────────────────────
    # What was scanned — the URL, email sender address, or APK filename.
    # Shown in the history table as a human-readable label.
    input_summary: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)

    # ── Score outputs ─────────────────────────────────────────────────────────
    trust_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=False)

    # ── Raw signal data (all check outputs) ──────────────────────────────────
    # Stored as JSON so we don't need schema changes when adding new signals.
    raw_results: Mapped[dict] = mapped_column(JSON, nullable=True)

    # ── LLM explanation ───────────────────────────────────────────────────────
    explanation: Mapped[str] = mapped_column(Text, nullable=True)

    # ── Timestamp ─────────────────────────────────────────────────────────────
    # server_default=func.now() → DB fills this automatically on INSERT.
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # ── ORM relationship ──────────────────────────────────────────────────────
    # scan.user gives us the User object associated with this scan.
    user = relationship("User", back_populates="scans")
