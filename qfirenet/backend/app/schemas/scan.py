"""
schemas/scan.py — Pydantic request/response schemas for all scan types.

Pydantic schemas serve a different purpose than SQLAlchemy models:
  - SQLAlchemy models describe how data is *stored* in the database.
  - Pydantic schemas describe how data is *transferred* over HTTP (JSON).

FastAPI uses Pydantic schemas to:
  1. Parse & validate incoming JSON request bodies.
  2. Serialize outgoing Python objects into JSON responses.
  3. Auto-generate the OpenAPI (Swagger) documentation.
"""

from datetime import datetime
from typing import Optional, Any

from pydantic import BaseModel, HttpUrl, Field


# ─────────────────────────────────────────────────────────────────────────────
# WEBSITE SCAN SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────

class WebsiteScanRequest(BaseModel):
    """Body of POST /scan/website."""
    url: HttpUrl = Field(
        ...,
        description="The full URL of the website to scan.",
        examples=["https://example.com"],
    )


class SSLResult(BaseModel):
    """Result from the SSL/TLS certificate check."""
    is_valid: Optional[bool] = None
    issuer: Optional[str] = None
    expiry_date: Optional[str] = None
    days_until_expiry: Optional[int] = None
    tls_version: Optional[str] = None
    error: Optional[str] = None


class WHOISResult(BaseModel):
    """Result from the WHOIS / domain-age check."""
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    is_recently_registered: Optional[bool] = None
    error: Optional[str] = None


class PhishingResult(BaseModel):
    """Result from the phishing-heuristics check (includes entropy signals)."""
    risk_indicators: list[str] = []
    heuristic_score: int = 0
    url_entropy: Optional[float] = None
    domain_entropy: Optional[float] = None


class PQCResult(BaseModel):
    """Result from the Post-Quantum Cryptography readiness check."""
    cipher_suite: Optional[str] = None
    tls_version: Optional[str] = None
    pqc_ready: bool = False
    note: Optional[str] = None
    error: Optional[str] = None


class WebsiteScanResponse(BaseModel):
    """Full JSON response from POST /scan/website."""
    scan_id: Optional[int] = None      # DB id — used to fetch full report later
    url: str
    trust_score: float = Field(..., ge=0, le=100)
    risk_level: str
    breakdown: dict[str, float]
    ssl: dict          # Raw dict — flexible for error states
    whois: dict
    phishing: dict
    pqc: dict
    explanation: str
    scanned_at: datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# EMAIL SCAN SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────

class EmailScanRequest(BaseModel):
    """
    Body of POST /scan/email (paste mode — application/json).

    Structured fields supplied directly by the user in the UI.
    Screenshot mode uses multipart/form-data with an UploadFile instead;
    both paths ultimately produce the same EmailScanResponse.
    """
    sender_email: Optional[str] = Field(
        default="",
        description="Sender's email address (e.g. 'support@example.com').",
        examples=["no-reply@paypal.com"],
    )
    subject: Optional[str] = Field(
        default="",
        description="Email subject line.",
        examples=["Your account has been suspended"],
    )
    body: Optional[str] = Field(
        default="",
        description="Plain-text email body content.",
    )
    # Legacy fields — kept for backward compatibility with any existing callers
    raw_headers: Optional[str] = Field(
        default="",
        description="(Legacy) Raw email header block. Prefer sender_email + subject + body.",
    )


class EmailScanResponse(BaseModel):
    """Full JSON response from POST /scan/email (both paste and screenshot modes)."""
    scan_id: Optional[int] = None      # DB id — used to fetch full report later
    trust_score: float = Field(..., ge=0, le=100)
    risk_level: str
    breakdown: dict[str, float]
    headers: dict      # SPF/DKIM/DMARC results
    content: dict      # Content heuristic results
    domain_check: Optional[dict] = None   # Rule-based sender domain verification result
    confidence_score: Optional[int] = Field(
        default=None,
        ge=0,
        le=100,
        description=(
            "LLM confidence in its verdict (0–100). "
            "Values below 60 indicate an 'Uncertain' verdict — not confidently scam or safe."
        ),
    )
    llm_verdict: Optional[str] = Field(
        default=None,
        description="LLM's explicit verdict: 'SCAM', 'LEGITIMATE', or 'UNCERTAIN'.",
    )
    llm_signals: Optional[list[str]] = Field(
        default=None,
        description="List of phishing signals the LLM identified in the email.",
    )
    input_mode: str = Field(
        default="paste",
        description="How the email was submitted: 'paste' or 'screenshot'.",
    )
    explanation: str
    scanned_at: datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# APK SCAN SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────

class APKScanResponse(BaseModel):
    """Full JSON response from POST /scan/apk."""
    scan_id: Optional[int] = None      # DB id — used to fetch full report later
    filename: str
    trust_score: float = Field(..., ge=0, le=100)
    risk_level: str
    breakdown: dict[str, float]
    extraction: dict   # App metadata + permissions list
    risk: dict         # Permission tier breakdown + risk score
    explanation: str
    scanned_at: datetime

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# HISTORY & REPORT SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────

class ScanHistoryItem(BaseModel):
    """
    One row in the scan history table.

    Exposes enough data to render rich history cards — score, risk badge,
    breakdown (for mini radar), and a short explanation preview.
    """
    id: int
    scan_type: str
    input_summary: str
    trust_score: float
    risk_level: str
    explanation: str
    scanned_at: datetime
    # breakdown is embedded in raw_results; we expose it here for UI charts
    # The history endpoint extracts it from raw_results on the fly.
    breakdown: Optional[dict[str, float]] = None

    model_config = {"from_attributes": True}


class ScanDetailResponse(BaseModel):
    """
    Full scan detail — returned by GET /report/{id}.
    Includes raw_results for deep inspection on the Results page.
    """
    id: int
    scan_type: str
    input_summary: str
    trust_score: float
    risk_level: str
    breakdown: Optional[dict[str, float]] = None
    raw_results: Optional[dict[str, Any]] = None
    explanation: str
    scanned_at: datetime

    model_config = {"from_attributes": True}


class ScanHistoryResponse(BaseModel):
    """Paginated scan history response."""
    items: list[ScanHistoryItem]
    total: int
    page: int
    page_size: int


# ─────────────────────────────────────────────────────────────────────────────
# STATS SCHEMA
# ─────────────────────────────────────────────────────────────────────────────

class StatsResponse(BaseModel):
    """Aggregated statistics for the /stats endpoint."""
    total_scans: int
    website_scans: int
    email_scans: int
    apk_scans: int
    avg_trust_score: float
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
