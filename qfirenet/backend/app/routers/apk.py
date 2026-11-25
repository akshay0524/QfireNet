"""
routers/apk.py — POST /scan/apk Route Handler

Orchestrates the Android APK analysis pipeline:
  1. Accept multipart file upload (UploadFile).
  2. Save temporarily to disk (androguard needs a file path).
  3. Extract permissions using androguard.
  4. Map permissions to risk tiers.
  5. Compute trust score.
  6. Generate LLM explanation.
  7. Persist to database.
  8. Delete the temp file (never persist APK binaries).
  9. Return full JSON response.

IMPORTANT — TEMP FILE HANDLING:
  We save the APK to a temporary directory, process it, then delete it.
  We NEVER store the APK binary in the database — only extracted metadata.
  The try/finally block guarantees cleanup even if an exception occurs.
"""

import asyncio
import os
import tempfile
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import ScanResult
from app.models.threat_event import ThreatEvent
from app.models.user import User
from app.auth.dependencies import get_optional_current_user
from app.modules.apk_scan.permission_extractor import extract_permissions
from app.modules.apk_scan.risk_mapper import map_permission_risk
from app.scoring.engine import calculate_apk_trust_score
from app.llm.explainer import generate_explanation
from app.schemas.scan import APKScanResponse


router = APIRouter(prefix="/scan", tags=["APK Scanner"])


async def _run_blocking(func, *args):
    """Run a blocking function in the asyncio thread pool."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, func, *args)


@router.post(
    "/apk",
    response_model=APKScanResponse,
    summary="Scan an Android APK file for dangerous permissions",
    description=(
        "Accepts an APK file upload. Extracts permissions using static analysis "
        "(no code is executed from the APK). Maps permissions to risk tiers and "
        "computes a trust score with LLM explanation. "
        "The APK file is deleted immediately after analysis."
    ),
)
async def scan_apk(
    file: UploadFile = File(..., description="Android APK file to analyse."),
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_optional_current_user),
):
    """
    POST /scan/apk

    Parameters
    ----------
    file         : UploadFile   — The uploaded APK file.
    db           : Session      — Database session (injected).
    current_user : User | None  — Authenticated user or None for anonymous.
    """
    # ── Validate file type ────────────────────────────────────────────────────
    original_filename = file.filename or "unknown.apk"
    if not original_filename.lower().endswith(".apk"):
        raise HTTPException(
            status_code=400,
            detail="Only .apk files are accepted. Please upload a valid Android APK.",
        )

    # ── Save to a temporary file ──────────────────────────────────────────────
    # We use tempfile.NamedTemporaryFile with delete=False so we can pass
    # the path to androguard (which needs a file path, not a file object).
    # The file is explicitly deleted in the finally block.
    tmp_path = None
    try:
        # Create temp file with .apk extension in the system temp directory.
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp_file:
            tmp_path = tmp_file.name
            content = await file.read()  # Read file bytes from the upload stream.
            tmp_file.write(content)      # Write to temp disk location.

        # ── Step 1: Extract permissions (static analysis) ─────────────────────
        extraction_result = await _run_blocking(extract_permissions, tmp_path)

        # ── Step 2: Map permissions to risk tiers ─────────────────────────────
        permissions = extraction_result.get("permissions", [])
        risk_result = await _run_blocking(map_permission_risk, permissions)

        apk_results = {
            "extraction": extraction_result,
            "risk":       risk_result,
        }

        # ── Step 3: Compute trust score ───────────────────────────────────────
        score_data = calculate_apk_trust_score(apk_results)

        # ── Step 4: LLM explanation ───────────────────────────────────────────
        explanation = await _run_blocking(
            generate_explanation, "apk", apk_results, score_data
        )

        # ── Step 5: Persist ───────────────────────────────────────────────────
        # Store the original filename as input_summary for history display.
        # We do NOT store the APK binary — only the metadata JSON.
        scan_record = ScanResult(
            user_id=current_user.id if current_user else None,
            scan_type="apk",
            input_summary=original_filename[:500],
            trust_score=score_data["overall_score"],
            risk_level=score_data["risk_level"],
            raw_results={**apk_results, "breakdown": score_data["breakdown"]},
            explanation=explanation,
            scanned_at=datetime.now(timezone.utc),
        )
        db.add(scan_record)
        db.commit()
        db.refresh(scan_record)

        # ── Log threat event for high-risk APK scans ─────────────────────────────
        # APKs have no IP to geolocate — we record lat/lng as 0 (equator/null island)
        # and the globe renderer skips points at exactly (0,0).
        if score_data["overall_score"] < 50:
            try:
                package_name = (
                    extraction_result.get("package_name")
                    or original_filename[:256]
                )
                threat = ThreatEvent(
                    scan_id      = scan_record.id,
                    scan_type    = "apk",
                    trust_score  = score_data["overall_score"],
                    entity       = package_name[:256],
                    lat          = 0.0,
                    lng          = 0.0,
                    country      = "Unknown",
                    country_code = "",
                    city         = "",
                )
                db.add(threat)
                db.commit()
            except Exception:
                pass  # Never let threat logging affect the scan response

        # ── Step 6: Return response ─────────────────────────────────────────────
        return APKScanResponse(
            scan_id=scan_record.id,
            filename=original_filename,
            trust_score=score_data["overall_score"],
            risk_level=score_data["risk_level"],
            breakdown=score_data["breakdown"],
            extraction=extraction_result,
            risk=risk_result,
            explanation=explanation,
            scanned_at=scan_record.scanned_at,
        )

    finally:
        # ── Always delete the temp file ───────────────────────────────────────
        # This runs even if an exception occurred — critical for security.
        # We never persist APK binaries; only extracted metadata is stored.
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass  # If deletion fails, it'll be cleaned up by the OS temp cleaner.
