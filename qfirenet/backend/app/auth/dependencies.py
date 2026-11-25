"""
auth/dependencies.py — FastAPI dependency for extracting the current user.

HOW FASTAPI DEPENDENCY INJECTION WORKS:
  When a route declares `current_user: User = Depends(get_current_user)`,
  FastAPI automatically calls get_current_user() before executing the route.
  If the dependency raises an HTTPException, the route never runs.

This pattern centralises authentication logic — every protected route gets
the same validation without duplicating code.

TWO VARIANTS:
  - get_current_user()          → raises 401 if no valid token (required auth)
  - get_optional_current_user() → returns None if no token (optional auth)

The optional variant is used for scan endpoints, where anonymous scans are
allowed but authenticated scans are saved to the user's history.
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.auth.utils import decode_access_token


# HTTPBearer extracts "Bearer <token>" from the Authorization header.
# auto_error=False means it returns None instead of raising 403 if the
# header is missing — we handle that ourselves in the dependency functions.
bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    """
    FastAPI dependency — extracts and validates the authenticated user.

    Raises HTTP 401 if:
      - No Authorization header is present.
      - The JWT is expired, invalid, or tampered with.
      - The user ID in the token doesn't exist in the database.

    Returns
    -------
    User
        The SQLAlchemy User object for the authenticated user.
    """
    # ── 1. Check header is present ────────────────────────────────────────────
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.  Include: Authorization: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ── 2. Decode and verify the JWT ──────────────────────────────────────────
    payload = decode_access_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is invalid or has expired.  Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ── 3. Look up the user in the database ───────────────────────────────────
    # 'sub' claim holds the user_id (stored as string per JWT convention).
    user_id = int(payload.get("sub", 0))
    user = db.query(User).filter(User.id == user_id).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found.  The account may have been deleted.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def get_optional_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User | None:
    """
    FastAPI dependency — returns the authenticated user OR None for anonymous.

    Used by scan endpoints that work for both anonymous and authenticated users.
    Anonymous scans are still processed — they just aren't saved to user history.

    Returns
    -------
    User | None
        The User object if a valid token is present, otherwise None.
    """
    if not credentials:
        return None  # Anonymous — no token provided, that's fine.

    payload = decode_access_token(credentials.credentials)
    if payload is None:
        return None  # Bad token — treat as anonymous (don't crash).

    user_id = int(payload.get("sub", 0))
    user = db.query(User).filter(User.id == user_id).first()
    return user  # Returns None if user not found (safe fallback)
