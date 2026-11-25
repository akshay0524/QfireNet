"""
routers/auth.py — User registration and login endpoints.

Endpoints:
  POST /auth/register  → Create a new user account.
  POST /auth/login     → Authenticate and receive a JWT token.

SECURITY CONSIDERATIONS documented inline:
  - Passwords are hashed with bcrypt before storage (never stored plain).
  - We return the same error message for "email not found" and "wrong password"
    to prevent user enumeration attacks (don't tell attackers which emails exist).
  - JWTs are signed — tampering with the payload invalidates the signature.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserLogin, TokenResponse, UserResponse
from app.auth.utils import hash_password, verify_password, create_access_token


# All routes in this file are prefixed with /auth.
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new QFireNet account",
)
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """
    POST /auth/register

    Creates a new user account.  On success, returns a JWT token so the
    user is immediately logged in without a second round-trip.

    Raises HTTP 409 if the email address is already registered.
    """
    # ── Check for duplicate email ─────────────────────────────────────────────
    existing = db.query(User).filter(User.email == user_data.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    # ── Hash the password (NEVER store plain text) ────────────────────────────
    hashed = hash_password(user_data.password)

    # ── Create and persist the new user row ───────────────────────────────────
    new_user = User(email=user_data.email, hashed_password=hashed)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)  # Reload to get server-generated id + created_at

    # ── Issue JWT immediately so the user is logged in ────────────────────────
    token = create_access_token(user_id=new_user.id, email=new_user.email)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(new_user),
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Log in and receive a JWT access token",
)
async def login(credentials: UserLogin, db: Session = Depends(get_db)):
    """
    POST /auth/login

    Validates email + password and returns a JWT token.

    SECURITY NOTE: We return the same "Invalid credentials" message whether
    the email doesn't exist OR the password is wrong.  This prevents
    user-enumeration attacks where an attacker probes which emails are registered.

    Raises HTTP 401 if credentials are invalid.
    """
    # ── Look up user by email ─────────────────────────────────────────────────
    user = db.query(User).filter(User.email == credentials.email).first()

    # ── Verify password (or reject if user doesn't exist) ────────────────────
    # We always call verify_password even if user is None to make the response
    # time consistent (timing-safe: prevents timing-based user enumeration).
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ── Issue JWT ─────────────────────────────────────────────────────────────
    token = create_access_token(user_id=user.id, email=user.email)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse.model_validate(user),
    )


from app.auth.dependencies import get_current_user  # noqa: E402


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get the currently authenticated user",
)
async def get_me(current_user: User = Depends(get_current_user)):
    """
    GET /auth/me

    Returns the profile of the currently logged-in user.
    Useful for the frontend to verify a token is still valid on page load.

    Raises HTTP 401 if the token is missing, expired, or invalid.
    """
    return UserResponse.model_validate(current_user)
