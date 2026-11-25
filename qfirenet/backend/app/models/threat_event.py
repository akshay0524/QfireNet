"""
models/threat_event.py — SQLAlchemy ORM model for the threat_events table.

PURPOSE:
  Whenever a scan returns a Trust Score below 50 (High Risk), a ThreatEvent
  record is created. These records power the Live Threat Activity Globe on
  the Dashboard, showing geolocated origins of flagged malicious entities
  (websites, email sender domains, APK packages).

PRIVACY:
  Only the FLAGGED MALICIOUS ENTITY is stored — the website domain/IP, email
  sender domain, or APK package name. The identity/IP of the user submitting
  the scan is NEVER stored or geolocated.
"""

from datetime import datetime

from sqlalchemy import Integer, Float, String, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.database import Base


class ThreatEvent(Base):
    """
    Represents one high-risk scan event, geolocated for the threat map globe.

    Columns:
      id          — Auto-incremented primary key.
      scan_id     — FK to scan_results.id (nullable — events may outlive scans).
      scan_type   — 'url' | 'email' | 'apk'
      trust_score — The computed trust score (0–49 for events recorded here).
      entity      — The flagged entity: domain, IP, sender domain, or APK name.
      lat         — Latitude of the flagged entity's geolocated server.
      lng         — Longitude of the flagged entity's geolocated server.
      country     — Country name from geolocation.
      country_code— ISO 3166-1 alpha-2 country code (e.g. 'US', 'CN').
      city        — City name from geolocation (may be empty).
      timestamp   — UTC time this event was created.
    """

    __tablename__ = "threat_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # FK to scan_results — nullable so events are preserved if scan row is deleted
    scan_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("scan_results.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # 'url' | 'email' | 'apk' — used for colour-coding arcs on the globe
    scan_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)

    # Trust score at time of scan (always < 50 for events stored here)
    trust_score: Mapped[float] = mapped_column(Float, nullable=False)

    # The flagged entity — domain, IP, sender address domain, or APK package name
    entity: Mapped[str] = mapped_column(String(512), nullable=False)

    # Geolocation fields — populated via ip-api.com free tier
    lat: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    lng: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    country: Mapped[str] = mapped_column(String(100), nullable=False, default="Unknown")
    country_code: Mapped[str] = mapped_column(String(5), nullable=False, default="")
    city: Mapped[str] = mapped_column(String(100), nullable=False, default="")

    # Timestamp (DB-filled automatically)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
