"""
routers/threat_events.py — GET /threat-events/recent

Returns recent high-risk scan events for the Live Threat Activity Globe on the dashboard.

ENDPOINTS:
  GET /threat-events/recent  — Last 200 events from the past 48 hours.
  GET /threat-events/stats   — Aggregated stats: today's count, high-risk count, country count.

PRIVACY:
  Only flagged malicious entities are returned — domains, IPs, sender domains, APK names.
  No user identity or submitter IP is ever exposed.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.threat_event import ThreatEvent

router = APIRouter(prefix="/threat-events", tags=["Threat Map"])


@router.get("/recent")
async def get_recent_threat_events(
    hours: int = Query(default=48, ge=1, le=168, description="Lookback window in hours"),
    limit: int = Query(default=200, ge=1, le=500, description="Max events to return"),
    db: Session = Depends(get_db),
):
    """
    GET /threat-events/recent

    Returns the most recent high-risk scan events for the globe threat map.
    Public endpoint — no authentication required.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    events = (
        db.query(ThreatEvent)
        .filter(ThreatEvent.timestamp >= cutoff)
        .order_by(ThreatEvent.timestamp.desc())
        .limit(limit)
        .all()
    )

    return {
        "events": [
            {
                "id":           e.id,
                "scan_type":    e.scan_type,
                "trust_score":  e.trust_score,
                "entity":       e.entity,
                "lat":          e.lat,
                "lng":          e.lng,
                "country":      e.country,
                "country_code": e.country_code,
                "city":         e.city,
                "timestamp":    e.timestamp.isoformat(),
            }
            for e in events
        ],
        "total": len(events),
        "lookback_hours": hours,
    }


@router.get("/stats")
async def get_threat_stats(db: Session = Depends(get_db)):
    """
    GET /threat-events/stats

    Aggregated stats for the Live Counter Panel beside the globe.
    Returns:
      - threats_today: events in the last 24 hours
      - high_risk_total: total all-time threat events stored
      - countries_flagged: distinct countries in the last 48 hours
    """
    now = datetime.now(timezone.utc)
    today_cutoff = now - timedelta(hours=24)
    week_cutoff  = now - timedelta(hours=48)

    threats_today = (
        db.query(func.count(ThreatEvent.id))
        .filter(ThreatEvent.timestamp >= today_cutoff)
        .scalar() or 0
    )

    high_risk_total = (
        db.query(func.count(ThreatEvent.id))
        .scalar() or 0
    )

    countries_flagged = (
        db.query(func.count(func.distinct(ThreatEvent.country_code)))
        .filter(
            ThreatEvent.timestamp >= week_cutoff,
            ThreatEvent.country_code != "",
        )
        .scalar() or 0
    )

    return {
        "threats_today":    threats_today,
        "high_risk_total":  high_risk_total,
        "countries_flagged": countries_flagged,
    }
