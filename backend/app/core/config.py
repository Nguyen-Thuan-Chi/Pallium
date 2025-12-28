# backend/app/core/config.py
"""
Production-ready configuration using pydantic-settings.

Security considerations:
- No hardcoded secrets in production (SECRET_KEY must be set via env)
- CORS_ORIGINS parsed from comma-separated env var, never defaults to "*"
- Database URLs normalized for async drivers automatically
- Debug/echo modes disabled in production by default
"""
from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Strictly typed application settings.

    Priority for loading:
    1. Environment variables (highest priority)
    2. .env file (via pydantic-settings)
    3. Default values (lowest priority, dev-safe only)
    """

    # ─────────────────────────────────────────────────────────────
    # Application metadata
    # ─────────────────────────────────────────────────────────────
    PROJECT_NAME: str = "Pallium"
    PROJECT_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # ─────────────────────────────────────────────────────────────
    # Environment mode
    # Used to toggle behaviors between dev/production safely
    # ─────────────────────────────────────────────────────────────
    ENVIRONMENT: str = "development"

    # ─────────────────────────────────────────────────────────────
    # Security: JWT Configuration
    # SECRET_KEY MUST be set in production via environment variable
    # ─────────────────────────────────────────────────────────────
    SECRET_KEY: str = "INSECURE_DEV_KEY_CHANGE_IN_PRODUCTION"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # ─────────────────────────────────────────────────────────────
    # Database Configuration
    # Priority: DATABASE_URL env var → SQLite fallback for local dev
    #
    # Render.com provides DATABASE_URL with postgres:// scheme.
    # We normalize to postgresql+asyncpg:// for SQLAlchemy async.
    # ─────────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./pallium.db"

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def normalize_database_url(cls, v: str) -> str:
        """
        Normalize database URLs for async SQLAlchemy compatibility.

        Conversions:
        - postgres://     → postgresql+asyncpg://  (Render.com style)
        - postgresql://   → postgresql+asyncpg://  (standard PostgreSQL)
        - sqlite:///      → sqlite+aiosqlite:///   (local development)

        Security: This runs before value assignment, ensuring the URL
        is always in the correct format for async drivers.
        """
        if v is None:
            return "sqlite+aiosqlite:///./pallium.db"

        url = v.strip()

        # Handle Render.com style postgres:// URLs
        if url.startswith("postgres://"):
            return url.replace("postgres://", "postgresql+asyncpg://", 1)

        # Handle standard postgresql:// URLs (add asyncpg driver)
        if url.startswith("postgresql://") and "+asyncpg" not in url:
            return url.replace("postgresql://", "postgresql+asyncpg://", 1)

        # Handle SQLite URLs (ensure aiosqlite driver)
        if url.startswith("sqlite:///") and "+aiosqlite" not in url:
            return url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)

        return url

    # ─────────────────────────────────────────────────────────────
    # Database debugging
    # MUST be False in production to prevent SQL query exposure
    # ─────────────────────────────────────────────────────────────
    DATABASE_ECHO: bool = False

    # ─────────────────────────────────────────────────────────────
    # CORS Configuration
    # Parsed from comma-separated CORS_ORIGINS env var
    # Empty string → empty list (NOT "*" for security)
    # ─────────────────────────────────────────────────────────────
    CORS_ORIGINS: str = "http://localhost:5500,http://127.0.0.1:5500,http://localhost:8000,http://127.0.0.1:8000"

    @property
    def BACKEND_CORS_ORIGINS(self) -> List[str]:
        """
        Parse CORS_ORIGINS string into a list of allowed origins.

        Security considerations:
        - Empty string returns empty list, NOT wildcard "*"
        - Whitespace is trimmed from each origin
        - Empty entries after split are filtered out

        Returns:
            List of allowed origin URLs
        """
        if not self.CORS_ORIGINS or not self.CORS_ORIGINS.strip():
            return []

        return [
            origin.strip()
            for origin in self.CORS_ORIGINS.split(",")
            if origin.strip()
        ]

    # ─────────────────────────────────────────────────────────────
    # Pydantic Settings Configuration
    # ─────────────────────────────────────────────────────────────
    model_config = SettingsConfigDict(
        # Load from .env file if present (useful for local development)
        env_file=".env",
        env_file_encoding="utf-8",
        # Environment variables are case-insensitive
        case_sensitive=False,
        # Extra fields in .env are ignored (prevents config injection)
        extra="ignore",
    )

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.ENVIRONMENT.lower() == "production"

    @property
    def is_sqlite(self) -> bool:
        """Check if using SQLite database (local development)."""
        return "sqlite" in self.DATABASE_URL.lower()


@lru_cache()
def get_settings() -> Settings:
    """
    Cached settings instance.

    Using lru_cache ensures settings are only loaded once,
    providing consistent configuration across the application
    and avoiding repeated env var parsing.
    """
    return Settings()


# Default settings instance for backward compatibility
# Existing code imports `settings` directly from this module
settings = get_settings()
