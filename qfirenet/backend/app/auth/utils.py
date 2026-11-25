"""
auth/utils.py — JWT token creation/verification and password hashing.

This module has two responsibilities:
  1. PASSWORD HASHING: Convert plain-text passwords into bcrypt hashes,
     and verify a plain-text password against a stored hash.
  2. JWT TOKENS: Create signed tokens that encode the user's identity,
     and decode/verify tokens from incoming HTTP requests.

HOW JWT WORKS (BRIEF):
  A JWT is three base64-encoded strings joined by dots:
    header.payload.signature
  The server signs the payload with the SECRET KEY.  Clients send the token
  back with each request.  The server re-verifies the signature — if it
  matches, the payload is trusted without hitting the database.

WHY BCRYPT?
  bcrypt is slow by design (it runs many rounds of hashing).  This makes
  brute-force attacks computationally expensive even if the hash DB leaks.
"""

from datetime import datetime, timedelta, timezone

import bcrypt
from jose import JWTError, jwt

from app.config import settings


# ── Password hashing ──────────────────────────────────────────────────────────
# Using the `bcrypt` package directly instead of passlib, which has a
# compatibility bug with Python 3.12 (raises ValueError in wrap-bug detection).
# bcrypt.hashpw / bcrypt.checkpw are the battle-tested primitives underneath.
_BCRYPT_ROUNDS = 12  # Work factor — increase to 13-14 for production


def hash_password(plain_password: str) -> str:
    """
    Hash a plain-text password using bcrypt.

    This is called once during registration.  The result is stored in the DB.

    Parameters
    ----------
    plain_password : str
        The raw password as typed by the user.

    Returns
    -------
    str
        A bcrypt hash string (e.g. "$2b$12$...").
    """
    salt = bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain-text password against a stored bcrypt hash.

    Called during login.  Returns True if the password matches, False otherwise.
    bcrypt.checkpw is intrinsically timing-safe — it runs the full comparison
    even on early mismatch, resisting timing-based user enumeration.

    Parameters
    ----------
    plain_password   : str  — The password the user typed at login.
    hashed_password  : str  — The bcrypt hash stored in the database.
    """
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )


# ── JWT token utilities ───────────────────────────────────────────────────────

def create_access_token(user_id: int, email: str) -> str:
    """
    Create a signed JWT access token encoding the user's identity.

    The token expires after settings.JWT_EXPIRE_MINUTES minutes.
    The client should store this token and include it in the
    Authorization header of every authenticated request:
        Authorization: Bearer <token>

    Parameters
    ----------
    user_id : int  — The user's database primary key.
    email   : str  — The user's email address (for display purposes in the payload).

    Returns
    -------
    str
        A signed JWT string.
    """
    # The payload (called "claims" in JWT terminology) is the data we encode.
    # 'sub' (subject) is the standard JWT claim for user identity.
    # 'exp' (expiry) tells the token when it should stop being accepted.
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)

    payload = {
        "sub": str(user_id),   # User ID as string (JWT standard: sub is a string)
        "email": email,         # Email for convenience (not security-critical)
        "iat": now,             # Issued-at timestamp
        "exp": expire,          # Expiry timestamp
    }

    # jose.jwt.encode() signs the payload with our secret key and algorithm.
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token


def decode_access_token(token: str) -> dict | None:
    """
    Decode and verify a JWT access token.

    Returns the payload dict if the token is valid and not expired.
    Returns None if the token is invalid, expired, or tampered with.

    Parameters
    ----------
    token : str  — The raw JWT string from the Authorization header.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except JWTError:
        # JWTError covers: expired tokens, invalid signatures, malformed tokens.
        return None
