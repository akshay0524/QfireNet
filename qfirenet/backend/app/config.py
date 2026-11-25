"""
config.py — Application-wide settings loaded from environment variables.

We use pydantic-settings (BaseSettings) which automatically reads values from
a .env file or the system environment.  Any key here can be overridden by simply
setting the matching env-var before starting the server — no code change needed.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central configuration object for QFireNet backend.

    pydantic-settings will:
      1. Look for each field name as an environment variable (case-insensitive).
      2. Fall back to the value declared in the .env file (specified by env_file below).
      3. Use the Python default if neither source provides a value.
    """

    # ── Database ───────────────────────────────────────────────────────────────
    # Full PostgreSQL connection string.
    # Format: postgresql://user:password@host:port/dbname
    DATABASE_URL: str = "postgresql://postgres:password@localhost:5432/qfirenet"

    # ── Groq LLM ──────────────────────────────────────────────────────────────
    # API key obtained from https://console.groq.com
    GROQ_API_KEY: str = ""

    # Which Groq-hosted model to use for explanations.
    # llama-3.3-70b-versatile offers a good balance of speed and reasoning depth.
    GROQ_MODEL: str = "qwen/qwen3.8-27b"

    # Maximum tokens the LLM may return.  Explanations should be concise.
    GROQ_MAX_TOKENS: int = 512

    # ── JWT Authentication ─────────────────────────────────────────────────────
    # Secret key used to sign JWT tokens.  Must be a long random string.
    # Generate one with: python -c "import secrets; print(secrets.token_hex(32))"
    # NEVER commit the real value to git — use the .env file.
    JWT_SECRET_KEY: str = "change-me-in-production-use-secrets-token-hex-32"

    # Algorithm used to sign JWTs.  HS256 (HMAC + SHA-256) is the standard choice.
    JWT_ALGORITHM: str = "HS256"

    # How many minutes a JWT stays valid before the user must re-login.
    # 60 * 24 = 1440 minutes = 24 hours.
    JWT_EXPIRE_MINUTES: int = 1440

    # ── Application ───────────────────────────────────────────────────────────
    APP_NAME: str = "QFireNet"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Tells pydantic-settings to also load from a .env file in the working dir.
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


# Module-level singleton — import this object wherever settings are needed.
# Example:  from app.config import settings
#           print(settings.JWT_SECRET_KEY)
settings = Settings()
