# backend/app/models/seed_recovery.py
"""
ORM model for storing seed phrase recovery data.

Security: Only stores cryptographic verifier and salt.
The actual seed phrase is NEVER stored on the server.
"""
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from backend.app.db.base import Base


class SeedRecovery(Base):
    """
    Stores seed phrase verification data for password recovery.

    The seed phrase itself is never transmitted or stored.
    Only the verifier (hash of derived seed key) is stored.
    """
    __tablename__ = "seed_recovery"

    id = Column(Integer, primary_key=True, index=True)

    # Foreign key to user
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)

    # Salt used for PBKDF2 derivation (base64-encoded, 16 bytes)
    # This is generated server-side and sent to client during setup
    seed_salt = Column(String(64), nullable=False)

    # Verifier = SHA-256(seed_key) where seed_key = PBKDF2(seed_phrase, seed_salt)
    # Base64-encoded, 32 bytes (256 bits)
    seed_verifier = Column(String(64), nullable=False)

    # Whether seed recovery is enabled for this user
    is_enabled = Column(Boolean, default=True, nullable=False)

    # Timestamps for audit trail
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    # Track failed verification attempts (for rate limiting/lockout)
    failed_attempts = Column(Integer, default=0, nullable=False)
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)

