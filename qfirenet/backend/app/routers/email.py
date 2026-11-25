"""
routers/email.py — POST /scan/email Route Handler (v2 — Dual-Mode Input)

DUAL-MODE INPUT:
  This endpoint accepts two content types, both returning the same response schema:

  1. Paste Mode  (Content-Type: application/json)
     Body: { sender_email, subject, body }
     The user typed/pasted structured email fields directly in the UI.

  2. Screenshot Mode  (Content-Type: multipart/form-data)
     Fields: image=<file>, mode="screenshot"
     The user uploaded a screenshot; backend runs OCR to extract text,
     validates OCR quality, then feeds into the same pipeline as paste mode.

PIPELINE (both modes):
  1. Extract sender_email, subject, body  (paste: from JSON; screenshot: from OCR)
  2. Validate sender email format (basic regex).
  3. Rule-based domain check  (safe-domain list + lookalike detection).
  4. Run email header mock check on synthesized From / Subject headers.
  5. Run content heuristic check on the body text.
  6. LLM analysis (improved structured prompt with few-shot examples + confidence score).
  7. Blend LLM confidence + domain check into the trust score.
  8. Persist + return unified EmailScanResponse.

ACCURACY IMPROVEMENTS (v2):
  - Stronger structured LLM prompt checking 10 explicit phishing signal categories.
  - Confidence score (0–100) returned alongside verdict; low-confidence → UNCERTAIN.
  - 5 few-shot examples in system prompt to anchor model judgment.
  - Rule-based domain check layered independently of LLM.
  - OCR quality gate prevents garbled text from reaching the LLM.
  - JSONL logging of all LLM I/O pairs for prompt refinement.
"""

import asyncio
import re
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import ScanResult
from app.models.threat_event import ThreatEvent
from app.models.user import User
from app.auth.dependencies import get_optional_current_user
from app.modules.email_scan.header_check import check_email_headers
from app.modules.email_scan.content_check import check_email_content
from app.modules.email_scan.domain_checker import check_sender_domain
from app.modules.email_scan.ocr_extractor import extract_email_from_image
from app.modules.geolocator import geolocate
from app.scoring.engine import calculate_email_trust_score
from app.llm.explainer import generate_email_analysis, generate_explanation
from app.schemas.scan import EmailScanRequest, EmailScanResponse


router = APIRouter(prefix="/scan", tags=["Email Scanner"])

# Simple email format validator
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")


async def _run_blocking(func, *args):
    """Run a blocking function in the asyncio thread pool."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, func, *args)


def _synthesize_headers_string(sender_email: str, subject: str, reply_to: str = "") -> str:
    """
    Build a minimal RFC 5322-style header block from structured fields.
    This lets us re-use the existing header_check parser even when the user
    submitted structured fields instead of raw headers.
    """
    lines = []
    if sender_email:
        lines.append(f"From: {sender_email}")
        lines.append(f"Return-Path: <{sender_email}>")
    if subject:
        lines.append(f"Subject: {subject}")
    if reply_to:
        lines.append(f"Reply-To: {reply_to}")
    return "\n".join(lines)


async def _run_email_pipeline(
    sender_email: str,
    subject: str,
    body: str,
    input_mode: str,
    db: Session,
    current_user,
) -> EmailScanResponse:
    """
    Shared pipeline for both paste and screenshot modes.

    Accepts pre-extracted structured fields and runs:
      header check → content check → domain check → LLM → scoring → persist
    """

    # ── Validate sender email format ─────────────────────────────────────────
    if sender_email and not _EMAIL_RE.match(sender_email.strip()):
        raise HTTPException(
            status_code=400,
            detail=(
                f"'{sender_email}' does not look like a valid email address. "
                "Please check the sender field."
            ),
        )

    # ── Step 1: Rule-based domain check (independent of LLM) ─────────────────
    domain_check = await _run_blocking(check_sender_domain, sender_email)

    # ── Step 2: Build synthetic headers + run header check ────────────────────
    synthetic_headers = _synthesize_headers_string(sender_email, subject)
    header_result = await _run_blocking(check_email_headers, synthetic_headers)

    # ── Step 3: Content heuristic check ──────────────────────────────────────
    full_text_for_content = f"Subject: {subject}\n\n{body}" if subject else body
    content_result = await _run_blocking(check_email_content, full_text_for_content)

    email_results = {"headers": header_result, "content": content_result}

    # ── Step 4: LLM analysis (structured prompt + confidence score) ───────────
    llm_result = await _run_blocking(
        generate_email_analysis,
        sender_email,
        subject,
        body,
        header_result,
        domain_check,
        content_result,
    )

    llm_confidence = llm_result.get("confidence")   # int 0–100
    llm_verdict    = llm_result.get("verdict")       # SCAM / LEGITIMATE / UNCERTAIN
    llm_signals    = llm_result.get("triggered_signals", [])
    full_explanation = llm_result.get("full_explanation") or llm_result.get("explanation", "")

    # ── Step 5: Score (blending heuristics + LLM confidence + domain check) ──
    score_data = calculate_email_trust_score(
        email_results,
        llm_confidence=llm_confidence,
        domain_check=domain_check,
    )

    # ── Step 6: Build input summary for history display ───────────────────────
    input_summary = (
        f"[{input_mode.upper()}] "
        + (f"{sender_email[:80]} — " if sender_email else "")
        + (subject[:80] if subject else "Email scan")
    )

    # ── Step 7: Persist ───────────────────────────────────────────────────────
    raw_results_payload = {
        **email_results,
        "domain_check":  domain_check,
        "llm_verdict":   llm_verdict,
        "llm_confidence": llm_confidence,
        "llm_signals":   llm_signals,
        "input_mode":    input_mode,
        "breakdown":     score_data["breakdown"],
    }

    scan_record = ScanResult(
        user_id       = current_user.id if current_user else None,
        scan_type     = "email",
        input_summary = input_summary,
        trust_score   = score_data["overall_score"],
        risk_level    = score_data["risk_level"],
        raw_results   = raw_results_payload,
        explanation   = full_explanation,
        scanned_at    = datetime.now(timezone.utc),
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)

    # ── Log threat event for high-risk email scans (fire-and-forget) ─────────
    # Geolocate the sender domain. Never geolocate the submitter's IP.
    if score_data["overall_score"] < 50 and sender_email:
        try:
            sender_domain = sender_email.split("@")[-1] if "@" in sender_email else sender_email
            geo = await _run_blocking(geolocate, sender_domain)
            threat = ThreatEvent(
                scan_id     = scan_record.id,
                scan_type   = "email",
                trust_score = score_data["overall_score"],
                entity      = sender_email[:256],
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

    # ── Step 8: Return unified response ──────────────────────────────────────
    return EmailScanResponse(
        scan_id          = scan_record.id,
        trust_score      = score_data["overall_score"],
        risk_level       = score_data["risk_level"],
        breakdown        = score_data["breakdown"],
        headers          = header_result,
        content          = content_result,
        domain_check     = domain_check,
        confidence_score = llm_confidence,
        llm_verdict      = llm_verdict,
        llm_signals      = llm_signals,
        input_mode       = input_mode,
        explanation      = full_explanation,
        scanned_at       = scan_record.scanned_at,
    )


# ─────────────────────────────────────────────────────────────────────────────
# PASTE MODE  —  POST /scan/email  (application/json)
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/email",
    response_model=EmailScanResponse,
    summary="Scan email (paste mode) — structured fields",
    description=(
        "Paste mode: provide sender_email, subject, and body as JSON. "
        "Checks sender domain, scans body for scam content heuristics, "
        "and runs LLM analysis with confidence scoring. "
        "Returns a unified trust score with detailed breakdown."
    ),
)
async def scan_email_paste(
    request: EmailScanRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    sender_email = (request.sender_email or "").strip()
    subject      = (request.subject or "").strip()
    body         = (request.body or "").strip()

    # Support legacy raw_headers field: if someone sends raw_headers + body,
    # try to extract a From address from the headers block.
    if not sender_email and request.raw_headers:
        import re as _re
        m = _re.search(r"(?mi)^From\s*:\s*(.+)", request.raw_headers)
        if m:
            sender_email = m.group(1).strip()

    if not any([sender_email, subject, body]):
        raise HTTPException(
            status_code=400,
            detail="Please fill in at least one field: Sender Email, Subject, or Email Body.",
        )

    return await _run_email_pipeline(
        sender_email=sender_email,
        subject=subject,
        body=body,
        input_mode="paste",
        db=db,
        current_user=current_user,
    )


# ─────────────────────────────────────────────────────────────────────────────
# SCREENSHOT MODE  —  POST /scan/email/screenshot  (multipart/form-data)
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/email/screenshot",
    response_model=EmailScanResponse,
    summary="Scan email (screenshot mode) — OCR image upload",
    description=(
        "Screenshot mode: upload a PNG/JPG/JPEG screenshot of an email (max 5MB). "
        "OCR extracts sender, subject, and body text. "
        "Validates OCR quality before running analysis. "
        "Returns the same unified trust score as paste mode."
    ),
)
async def scan_email_screenshot(
    image: UploadFile = File(..., description="Email screenshot (.png, .jpg, .jpeg, max 5MB)"),
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user),
):
    # ── File type validation ──────────────────────────────────────────────────
    allowed_types = {"image/png", "image/jpeg", "image/jpg"}
    content_type  = (image.content_type or "").lower()
    filename_ext  = (image.filename or "").lower().rsplit(".", 1)[-1]

    if content_type not in allowed_types and filename_ext not in ("png", "jpg", "jpeg"):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported file type '{image.filename}'. "
                "Please upload a PNG or JPG/JPEG image."
            ),
        )

    # ── Read image bytes ──────────────────────────────────────────────────────
    image_bytes = await image.read()

    # ── OCR extraction (blocking — Tesseract is CPU-bound) ───────────────────
    try:
        ocr_result = await _run_blocking(extract_email_from_image, image_bytes)
    except ValueError as exc:
        # Validation errors (too large, bad format, garbled OCR)
        raise HTTPException(status_code=422, detail=str(exc))
    except RuntimeError as exc:
        # Tesseract not installed
        raise HTTPException(status_code=503, detail=str(exc))

    sender_email = ocr_result.get("sender_email", "")
    subject      = ocr_result.get("subject", "")
    body         = ocr_result.get("body", "")

    if not body.strip():
        raise HTTPException(
            status_code=422,
            detail=(
                "OCR extracted no usable body text from the image. "
                "Please upload a clearer, higher-resolution screenshot."
            ),
        )

    return await _run_email_pipeline(
        sender_email=sender_email,
        subject=subject,
        body=body,
        input_mode="screenshot",
        db=db,
        current_user=current_user,
    )
