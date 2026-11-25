"""
routers/history.py — GET /history and GET /history/{id} Route Handlers

Returns paginated scan history for the authenticated user, with rich
breakdown data for UI visualization (mini radar charts in history cards).

AUTHENTICATION REQUIRED:
  Anonymous users have no account, so they can't retrieve history.
  Both endpoints always require a valid JWT.
PAGINATION:
  The list endpoint supports cursor-style pagination via `page` and
  `page_size` query params. Default: page=1, page_size=20.
BREAKDOWN EXTRACTION:
  The breakdown dict is embedded inside raw_results (not a top-level DB
  column). We extract it here so the frontend can render mini charts
  without a second API call to /report/{id}.
"""
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.scan import ScanResult
from app.models.user import User
from app.auth.dependencies import get_current_user
from app.schemas.scan import ScanDetailResponse, ScanHistoryResponse, ScanHistoryItem
router = APIRouter(prefix="/history", tags=["Scan History"])
def _extract_breakdown_from_raw(raw_results: dict | None) -> dict | None:
    """
    Pull the 'breakdown' key out of raw_results if it was stored there.

    Each router stores score_data into the scan record's raw_results.
    The breakdown lives at raw_results['breakdown'] if stored, else None.
    """
    if not raw_results:
        return None
    return raw_results.get("breakdown")


@router.get(
    "",
    response_model=ScanHistoryResponse,
    summary="Get authenticated user's scan history",
    description=(
        "Returns a paginated list of past scans for the logged-in user. "
        "Ordered by most recent first.  Requires a valid JWT token. "
        "Each item includes the score breakdown for mini-chart rendering."
    ),
)
async def get_scan_history(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)."),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page (max 100)."),
    scan_type: str | None = Query(default=None, description="Filter by scan type: website, email, apk."),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),  # Required auth — raises 401 if missing
):
    """
    GET /history?page=1&page_size=20&scan_type=website

    Parameters
    ----------
    page       : int       — Which page to return (starts at 1).
    page_size  : int       — How many results per page (capped at 100).
    scan_type  : str|None  — Optional filter by scan type.
    db         : Session   — Database session.
    current_user : User    — The authenticated user (raises 401 if not authenticated).
    """
    # ── Build base query ──────────────────────────────────────────────────────
    query = db.query(ScanResult).filter(ScanResult.user_id == current_user.id)

    # Optional filter by scan type
    if scan_type:
        query = query.filter(ScanResult.scan_type == scan_type)

    # ── Count total scans for this user ───────────────────────────────────────
    total = query.count()

    # ── Fetch the requested page ──────────────────────────────────────────────
    offset = (page - 1) * page_size
    scans = (
        query
        .order_by(ScanResult.scanned_at.desc())
        .offset(offset)
        .limit(page_size)
        .all()
    )

    # ── Serialize with breakdown extracted from raw_results ───────────────────
    items = [
        ScanHistoryItem(
            id=scan.id,
            scan_type=scan.scan_type,
            input_summary=scan.input_summary,
            trust_score=scan.trust_score,
            risk_level=scan.risk_level,
            explanation=scan.explanation or "",
            scanned_at=scan.scanned_at,
            breakdown=_extract_breakdown_from_raw(scan.raw_results),
        )
        for scan in scans
    ]

    return ScanHistoryResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Get a single scan from history by ID",
    description=(
        "Returns the full detail of a single past scan. "
        "Useful for navigating to a previous result without re-scanning. "
        "Requires a valid JWT — you can only view your own scans."
    ),
)
async def get_history_item(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    GET /history/{scan_id}

    Retrieves a single scan record with full raw_results for detail display.
    """
    scan = db.query(ScanResult).filter(
        ScanResult.id == scan_id,
        ScanResult.user_id == current_user.id,  # ownership enforced
    ).first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan #{scan_id} not found in your history.",
        )

    return ScanDetailResponse(
        id=scan.id,
        scan_type=scan.scan_type,
        input_summary=scan.input_summary,
        trust_score=scan.trust_score,
        risk_level=scan.risk_level,
        breakdown=_extract_breakdown_from_raw(scan.raw_results),
        raw_results=scan.raw_results,
        explanation=scan.explanation or "",
        scanned_at=scan.scanned_at,
    )
