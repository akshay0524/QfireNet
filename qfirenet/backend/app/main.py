"""
main.py — QFireNet FastAPI Application Entry Point

This file wires everything together:
  1. Creates the FastAPI application instance.
  2. Registers all routers (URL prefixes and route handlers).
  3. Sets up database table creation on startup.
  4. Configures CORS so the React frontend can call the backend.
  5. Adds health-check and stats endpoints.
  6. Applies rate limiting via slowapi.

HOW FASTAPI WORKS (BRIEF):
  FastAPI is a Python web framework that uses Python type hints + Pydantic to
  automatically validate incoming requests and generate OpenAPI documentation.
  When you start uvicorn (the ASGI server), it loads this file and begins
  listening for HTTP requests.

API ROUTES REGISTERED:
  /auth/register          POST  — Create new account
  /auth/login             POST  — Log in, receive JWT
  /scan/website           POST  — Website trust scan
  /scan/email             POST  — Email scam scan (paste mode: JSON body)
  /scan/email/screenshot  POST  — Email scam scan (screenshot mode: multipart/form-data)
  /scan/apk               POST  — APK permission scan
  /history                GET   — Authenticated user's scan history (paginated)
  /history/{id}           GET   — Single scan history item detail
  /report/{id}            GET   — Full scan report by ID
  /stats                  GET   — Aggregated platform statistics
  /threat-events/recent   GET   — Recent high-risk events for globe (public)
  /threat-events/stats    GET   — Aggregated threat stats for counter panel (public)
  /                       GET   — Health check
  /health                 GET   — Health check (explicit)
  /docs                   GET   — Swagger UI (auto-generated)
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func

from app.config import settings
from app.database import engine, Base, SessionLocal

# Import all SQLAlchemy models so Base.metadata knows about all tables.
import app.models.user         # noqa: F401
import app.models.scan         # noqa: F401
import app.models.threat_event # noqa: F401

from app.models.scan import ScanResult

# Routers
from app.routers import website, email, apk, auth, history, report, threat_events


# ── Lifespan handler ──────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.

    On startup  → create all database tables if they don't exist.
    On shutdown → (nothing needed; SQLAlchemy closes connections automatically).
    """
    Base.metadata.create_all(bind=engine, checkfirst=True)
    print("[OK] Database tables created/verified.")
    print(f"[START] QFireNet {settings.APP_VERSION} starting up.")
    yield
    print("[STOP] QFireNet shutting down.")


# ── FastAPI application instance ──────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "QFireNet — AI-Powered Digital Trust & Cyber Risk Assessment Platform. "
        "Analyse websites, emails, and Android APKs for cyber risk signals. "
        "Scores are explained in plain English by Groq (Llama 3.3 70B). "
        "Includes Post-Quantum Cryptography (PQC) readiness checks."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# ── CORS Middleware ───────────────────────────────────────────────────────────
# Browsers block cross-origin requests unless the server explicitly allows them.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://localhost:80",
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ],
    allow_origin_regex=r"https://.*\.onrender\.com",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Simple in-memory rate limiter middleware ──────────────────────────────────
# Uses a sliding-window counter per client IP.
# For production, replace with Redis-backed slowapi or similar.
_rate_store: dict[str, list] = {}
RATE_LIMIT_REQUESTS = 30   # max requests per window
RATE_LIMIT_WINDOW   = 60   # seconds

import time

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """
    Lightweight in-process rate limiter.

    Allows up to RATE_LIMIT_REQUESTS per client IP within RATE_LIMIT_WINDOW seconds.
    Only applies to POST /scan/* endpoints (analysis is the expensive operation).
    Scan endpoints are the resource-intensive paths that need protection.
    """
    if request.method == "POST" and request.url.path.startswith("/scan"):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window_start = now - RATE_LIMIT_WINDOW

        # Prune timestamps outside the current window
        timestamps = _rate_store.get(client_ip, [])
        timestamps = [t for t in timestamps if t > window_start]

        if len(timestamps) >= RATE_LIMIT_REQUESTS:
            return JSONResponse(
                status_code=429,
                content={
                    "detail": (
                        f"Rate limit exceeded: max {RATE_LIMIT_REQUESTS} scan requests "
                        f"per {RATE_LIMIT_WINDOW}s per IP. Please wait before scanning again."
                    )
                },
            )

        timestamps.append(now)
        _rate_store[client_ip] = timestamps

    return await call_next(request)


# ── Register routers ──────────────────────────────────────────────────────────
app.include_router(auth.router)           # /auth/register, /auth/login
app.include_router(website.router)        # /scan/website
app.include_router(email.router)          # /scan/email
app.include_router(apk.router)            # /scan/apk
app.include_router(history.router)        # /history, /history/{id}
app.include_router(report.router)         # /report/{id}
app.include_router(threat_events.router)  # /threat-events/recent, /threat-events/stats


# ── Health check endpoints ────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
async def root():
    """Simple health check. Returns 200 OK with basic app info."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "scan_types": ["website", "email", "apk"],
    }


@app.get("/health", tags=["Health"])
async def health():
    """Explicit health endpoint for monitoring systems and Docker healthchecks."""
    return {"status": "ok"}


# ── Stats endpoint ────────────────────────────────────────────────────────────
@app.get("/stats", tags=["Statistics"])
async def get_stats():
    """
    GET /stats

    Returns aggregated platform statistics across all scans.
    Public endpoint — no authentication required.
    Used by the landing page to show trust metrics.
    """
    db = SessionLocal()
    try:
        total = db.query(func.count(ScanResult.id)).scalar() or 0
        website_count = db.query(func.count(ScanResult.id)).filter(ScanResult.scan_type == "website").scalar() or 0
        email_count   = db.query(func.count(ScanResult.id)).filter(ScanResult.scan_type == "email").scalar() or 0
        apk_count     = db.query(func.count(ScanResult.id)).filter(ScanResult.scan_type == "apk").scalar() or 0
        avg_score     = db.query(func.avg(ScanResult.trust_score)).scalar() or 0.0
        high_risk     = db.query(func.count(ScanResult.id)).filter(ScanResult.risk_level == "High").scalar() or 0
        medium_risk   = db.query(func.count(ScanResult.id)).filter(ScanResult.risk_level == "Medium").scalar() or 0
        low_risk      = db.query(func.count(ScanResult.id)).filter(ScanResult.risk_level == "Low").scalar() or 0

        return {
            "total_scans": total,
            "website_scans": website_count,
            "email_scans": email_count,
            "apk_scans": apk_count,
            "avg_trust_score": round(float(avg_score), 1),
            "high_risk_count": high_risk,
            "medium_risk_count": medium_risk,
            "low_risk_count": low_risk,
        }
    finally:
        db.close()
