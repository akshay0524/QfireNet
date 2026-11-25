"""
schemas/user.py — Pydantic request/response schemas for user auth.

IMPORTANT DISTINCTION:
  - models/user.py  describes the DATABASE row (SQLAlchemy ORM).
  - schemas/user.py describes the HTTP JSON payloads (Pydantic).

We NEVER expose hashed_password in API responses — only email + id + created_at.
"""

from datetime import datetime
from pydantic import BaseModel, EmailStr, Field


# ── Request Schemas ───────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    """
    Body of the POST /auth/register request.

    EmailStr validates that the string looks like a real email address.
    The password must be at least 8 characters long (min_length validation).
    """
    email: EmailStr = Field(..., description="Valid email address for the new account.")
    password: str = Field(..., min_length=8, description="Password (minimum 8 characters).")


class UserLogin(BaseModel):
    """
    Body of the POST /auth/login request.

    We accept the same fields as UserCreate — we intentionally keep login
    and registration separate so we can add registration-only fields later
    (e.g. display_name) without breaking login.
    """
    email: EmailStr = Field(..., description="Registered email address.")
    password: str = Field(..., description="Account password.")


# ── Response Schemas ──────────────────────────────────────────────────────────

class UserResponse(BaseModel):
    """
    Public representation of a User — safe to send in API responses.

    Note: hashed_password is intentionally EXCLUDED.
    """
    id: int
    email: str
    created_at: datetime

    model_config = {"from_attributes": True}  # Allow building from SQLAlchemy model


class TokenResponse(BaseModel):
    """
    Response from POST /auth/login and POST /auth/register.

    access_token: The JWT the client should store and send as:
                  Authorization: Bearer <access_token>
    token_type:   Always "bearer" (OAuth2 convention).
    user:         Basic user info so the frontend can display "Logged in as X".
    """
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
