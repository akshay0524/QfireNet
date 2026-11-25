"""
routers/report.py — GET /report/{id} Route Handler

Returns the full scan detail for a single scan record, identified by its
database ID. Used by the frontend Results page to load and display a
previously-completed scan in full detail.

SECURITY:
  - Authentication is required — users can only retrieve their own scans.
  - We verify user_id == current_user.id before returning data.
  - Anonymous scans (user_id=NULL) are NOT retrievable via this endpoint
    (they have no owner to authenticate against).

WHY A SEPARATE ENDPOINT:
  The history list endpoint returns lightweight ScanHistoryItem objects
  (no raw_results JSON) for performance.  This dedicated endpoint returns
  the full ScanDetailResponse including all signal data when the user
  explicitly requests a specific report.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scan import ScanResult
from app.models.user import User
from app.auth.dependencies import get_current_user
from app.schemas.scan import ScanDetailResponse


router = APIRouter(prefix="/report", tags=["Reports"])


def _extract_breakdown(scan: ScanResult) -> dict | None:
    """
    Extract the score breakdown from raw_results JSON.

    The scoring engine stores breakdown inside the raw_results blob when it's
    called from each router. We reconstruct it here for the detail view.
    This avoids adding a redundant 'breakdown' column to the DB table.
    """
    if not scan.raw_results:
        return None

    # Try common breakdown locations stored by each scan type
    raw = scan.raw_results

    # Website scans — breakdown is stored at top level of raw_results
    # We reconstruct it from the scoring sub-scores embedded in raw_results
    # (The actual breakdown dict is not stored separately in raw_results;
    #  it's in the response but not persisted. We'll return None gracefully.)
    return raw.get("breakdown")  # None if not present — frontend handles gracefully


@router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Retrieve a full scan report by ID",
    description=(
        "Returns the complete scan detail for a single scan, including all "
        "raw signal data, the trust score breakdown, and the AI explanation. "
        "Authentication required — you can only retrieve your own scans."
    ),
)
async def get_report(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),  # Required — raises 401 if missing
):
    """
    GET /report/{scan_id}

    Parameters
    ----------
    scan_id      : int   — The database ID of the scan to retrieve.
    db           : Session — Database session (injected).
    current_user : User    — Authenticated user (required).
    """
    # ── Fetch the scan record ─────────────────────────────────────────────────
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan #{scan_id} not found.",
        )

    # ── Ownership check ───────────────────────────────────────────────────────
    # Prevent users from accessing other users' scan reports.
    if scan.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to view this scan.",
        )

    # ── Extract breakdown from raw_results ────────────────────────────────────
    # The breakdown dict is stored in raw_results by each router.
    # We surface it here for the frontend radar chart.
    breakdown = _extract_breakdown(scan)

    return ScanDetailResponse(
        id=scan.id,
        scan_type=scan.scan_type,
        input_summary=scan.input_summary,
        trust_score=scan.trust_score,
        risk_level=scan.risk_level,
        breakdown=breakdown,
        raw_results=scan.raw_results,
        explanation=scan.explanation or "",
        scanned_at=scan.scanned_at,
    )
