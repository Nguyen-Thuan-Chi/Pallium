# backend/app/db/session.py
"""
Async database session management for SQLAlchemy.

Production considerations:
- Uses asyncpg for PostgreSQL (Render.com production)
- Uses aiosqlite for SQLite (local development fallback)
- Connection pooling configured for production workloads
- Pool settings differ for SQLite (no pooling) vs PostgreSQL

Security considerations:
- DATABASE_ECHO disabled by default (prevents SQL query exposure)
- Connection pool overflow limited to prevent resource exhaustion
- Pool pre-ping enabled to detect stale connections
"""
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool, AsyncAdaptedQueuePool

from backend.app.core.config import settings


def _create_async_engine() -> AsyncEngine:
    """
    Create and configure the async SQLAlchemy engine.

    Engine configuration differs based on database type:

    SQLite (local development):
    - Uses NullPool (SQLite doesn't support connection pooling well)
    - check_same_thread=False for async compatibility

    PostgreSQL (production):
    - Uses AsyncAdaptedQueuePool for connection pooling
    - pool_size=5: Baseline connections kept open
    - max_overflow=10: Additional connections under load
    - pool_pre_ping=True: Validate connections before use (prevents stale connection errors)
    - pool_recycle=300: Recycle connections every 5 minutes (Render may close idle connections)

    Returns:
        Configured AsyncEngine instance
    """
    # SQLite requires special handling for async
    if settings.is_sqlite:
        return create_async_engine(
            settings.DATABASE_URL,
            echo=settings.DATABASE_ECHO,
            # SQLite doesn't benefit from connection pooling
            # NullPool creates new connection per request
            poolclass=NullPool,
            # Required for SQLite async operations
            connect_args={"check_same_thread": False},
        )

    # PostgreSQL production configuration
    return create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DATABASE_ECHO,
        # Connection pool settings optimized for production
        poolclass=AsyncAdaptedQueuePool,
        # Number of persistent connections in pool
        pool_size=5,
        # Additional connections allowed during high load
        max_overflow=10,
        # Validate connection before checkout (prevents stale connection errors)
        # Critical for Render which may terminate idle connections
        pool_pre_ping=True,
        # Recycle connections every 5 minutes
        # Prevents issues with cloud database connection limits
        pool_recycle=300,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Global async engine instance
# Created once at module load, reused across all requests
# ─────────────────────────────────────────────────────────────────────────────
engine: AsyncEngine = _create_async_engine()


# ─────────────────────────────────────────────────────────────────────────────
# Async session factory
#
# expire_on_commit=False: Prevents attribute access errors after commit
# autoflush=False: Explicit flush control, prevents unexpected queries
# ─────────────────────────────────────────────────────────────────────────────
AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    # Prevent attribute expiration after commit
    # Allows accessing model attributes after session commit
    expire_on_commit=False,
    # Disable autoflush for explicit control over DB writes
    # Prevents unexpected queries during attribute access
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency generator for database sessions.

    Usage in FastAPI endpoints:
        @router.get("/items")
        async def get_items(db: AsyncSession = Depends(get_db)):
            ...

    Session lifecycle:
    - Creates new session per request
    - Yields session for endpoint use
    - Automatically closes session after request completes
    - Handles cleanup even if endpoint raises exception

    Note: This does NOT auto-commit. Endpoints must explicitly commit:
        await db.commit()

    Yields:
        AsyncSession bound to the configured database
    """
    async with AsyncSessionLocal() as session:
        yield session

