"""
routers/website.py — POST /scan/website Route Handler

This file registers the website scanning endpoint with FastAPI.
It is the "orchestrator" — it calls all four check modules concurrently,
feeds results to the scoring engine, gets an LLM explanation, saves to the
database, and returns the full JSON response.

KEY CONCEPT — async vs. sync in FastAPI:
  FastAPI is built on Starlette/asyncio.  When you mark a route with `async def`,
  the event loop can process other requests while THIS request is waiting on I/O
  (network calls, DB writes).  However, the four check functions use blocking
  Python code (socket, whois library).  We run them in a thread pool via
  asyncio.get_event_loop().run_in_executor() so they don't block the event loop.
"""

import asyncio
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import ScanResult
from app.models.threat_event import ThreatEvent
from app.models.user import User
from app.auth.dependencies import get_optional_current_user
from app.modules.website_scan.ssl_check import check_ssl
from app.modules.website_scan.whois_check import check_whois
from app.modules.website_scan.phishing_check import check_phishing_heuristics
from app.modules.website_scan.pqc_check import check_pqc_readiness
from app.modules.geolocator import geolocate
from app.scoring.engine import calculate_website_trust_score
from app.llm.explainer import generate_explanation
from app.schemas.scan import WebsiteScanRequest, WebsiteScanResponse


# APIRouter lets us group related routes together and register them in main.py
# with a common prefix.  All routes in this file will be prefixed with /scan.
router = APIRouter(prefix="/scan", tags=["Website Scanner"])


def _extract_hostname(url: str) -> str:
    """
    Extract the bare hostname from a full URL.

    Example: "https://www.example.com/path?q=1"  →  "www.example.com"

    We need just the hostname for socket-based checks (SSL, PQC) and WHOIS.
    """
    parsed = urlparse(str(url))
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Could not extract hostname from URL: {url}")
    return hostname


async def _run_blocking(func, *args):
    """
    Run a blocking (synchronous) function in a thread pool so it doesn't
    block the asyncio event loop.

    asyncio.get_event_loop().run_in_executor(None, ...) submits the function
    to the default ThreadPoolExecutor.  'None' means "use the default executor".

    Parameters
    ----------
    func : callable
        The synchronous function to run.
    *args : any
        Arguments to pass to the function.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, func, *args)


@router.post(
    "/website",
    response_model=WebsiteScanResponse,
    summary="Scan a website for trust and cyber-risk signals",
    description=(
        "Accepts a URL, runs four concurrent checks (SSL, WHOIS, Phishing, PQC), "
        "computes a weighted trust score, generates an AI explanation via Groq, "
        "and persists the result to PostgreSQL."
    ),
)
async def scan_website(
    request: WebsiteScanRequest,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
):
    """
    POST /scan/website

    Orchestrates the full website trust-scan pipeline:
      1. Validate and parse the URL.
      2. Run all four check modules concurrently (in thread pool).
      3. Compute the weighted trust score.
      4. Generate a plain-English explanation via Groq LLM.
      5. Persist the result to the database.
      6. Return the full result as JSON.

    Parameters
    ----------
    request      : WebsiteScanRequest  — Body must contain { "url": "https://example.com" }.
    db           : Session             — Injected by FastAPI's dependency system (from get_db).
    current_user : User | None         — Authenticated user or None for anonymous scan.
    """
    url_str = str(request.url)

    # ── Step 1: Extract hostname ──────────────────────────────────────────────
    try:
        hostname = _extract_hostname(url_str)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # ── Step 2: Run checks concurrently ──────────────────────────────────────
    # asyncio.gather() starts all coroutines at the same time and waits until
    # ALL of them finish.  This is like Promise.all() in JavaScript.
    # Each check is wrapped in _run_blocking so it runs in a thread pool.
    #
    # Important: return_exceptions=True means if one check fails,
    # the others still complete — we degrade gracefully instead of crashing.
    results = await asyncio.gather(
        _run_blocking(check_ssl, hostname),
        _run_blocking(check_whois, hostname),
        _run_blocking(check_phishing_heuristics, url_str),
        _run_blocking(check_pqc_readiness, hostname),
        return_exceptions=True,
    )

    ssl_result, whois_result, phishing_result, pqc_result = results

    # Wrap any exception results in a fallback dict with 'error' field.
    def _safe_result(result, default_keys: list) -> dict:
        if isinstance(result, Exception):
            return {"error": str(result), **{k: None for k in default_keys}}
        return result

    ssl_result      = _safe_result(ssl_result,      ["is_valid", "issuer", "expiry_date", "days_until_expiry", "tls_version"])
    whois_result    = _safe_result(whois_result,     ["domain_age_days", "registrar", "creation_date", "is_recently_registered"])
    phishing_result = _safe_result(phishing_result,  ["risk_indicators", "heuristic_score"])
    pqc_result      = _safe_result(pqc_result,       ["cipher_suite", "pqc_ready", "note"])

    # Bundle raw results for scoring and storage.
    website_results = {
        "ssl":      ssl_result,
        "whois":    whois_result,
        "phishing": phishing_result,
        "pqc":      pqc_result,
    }

    # ── Step 3: Compute trust score ───────────────────────────────────────────
    score_data = calculate_website_trust_score(website_results)

    # ── Step 4: Generate LLM explanation ─────────────────────────────────────
    # This is also blocking (HTTP call to Groq), so run it in the thread pool.
    explanation = await _run_blocking(
        generate_explanation, "website", website_results, score_data
    )

    # ── Step 5: Persist to database ───────────────────────────────────────────
    scan_record = ScanResult(
        user_id=current_user.id if current_user else None,
        scan_type="website",
        input_summary=url_str,
        trust_score=score_data["overall_score"],
        risk_level=score_data["risk_level"],
        raw_results={**website_results, "breakdown": score_data["breakdown"]},
        explanation=explanation,
        scanned_at=datetime.now(timezone.utc),
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    # ── Step 5b: Log threat event for high-risk scans (fire-and-forget) ──────
    # Only flag entities with Trust Score < 50. Geolocation is done in the
    # background via the thread pool — it never blocks the scan response.
    if score_data["overall_score"] < 50:
        try:
            geo = await _run_blocking(geolocate, hostname)
            threat = ThreatEvent(
                scan_id     = scan_record.id,
                scan_type   = "url",
                trust_score = score_data["overall_score"],
                entity      = hostname,
                lat         = geo["lat"],
                lng         = geo["lng"],
                country     = geo["country"],
                country_code= geo["country_code"],
                city        = geo["city"],
            )
            db.add(threat)
            db.commit()
        except Exception:
            pass  # Never let threat logging affect the scan response

    # ── Step 6: Build and return response ────────────────────────────────────
    return WebsiteScanResponse(
        scan_id=scan_record.id,
        url=url_str,
        trust_score=score_data["overall_score"],
        risk_level=score_data["risk_level"],
        breakdown=score_data["breakdown"],
        ssl=ssl_result,
        whois=whois_result,
        phishing=phishing_result,
        pqc=pqc_result,
        explanation=explanation,
        scanned_at=scan_record.scanned_at,
    )
