# backend/app/db/base.py
"""
SQLAlchemy declarative base and re-exports for backward compatibility.

This module defines the Base class for all ORM models and re-exports
database session components from db/session.py for backward compatibility.
"""
from sqlalchemy.orm import DeclarativeBase

# ─────────────────────────────────────────────────────────────────────────────
# Declarative Base for ORM Models
# All models inherit from this class
# ─────────────────────────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy ORM models.

    Usage:
        class User(Base):
            __tablename__ = "users"
            id = Column(Integer, primary_key=True)
            ...
    """
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Backward Compatibility Re-exports
#
# Existing code imports engine, get_db, AsyncSessionLocal from db.base
# These are now defined in db.session but re-exported here to avoid
# breaking existing imports throughout the codebase.
# ─────────────────────────────────────────────────────────────────────────────
from backend.app.db.session import (
    engine,
    AsyncSessionLocal,
    get_db,
)

# Explicit __all__ for clean imports
__all__ = [
    "Base",
    "engine",
    "AsyncSessionLocal",
    "get_db",
]
