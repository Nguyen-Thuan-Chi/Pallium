# backend/app/schemas/seed.py
"""
Pydantic schemas for seed phrase recovery endpoints.

All seed-related data validation happens here.
Note: seed_phrase is NEVER included in any schema -
it exists only on the client side.
"""
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class SeedSetupRequest(BaseModel):
    """
    Request to set up seed phrase recovery.

    Client sends:
    - seed_verifier: SHA-256 hash of the derived seed key
    - seed_salt: Salt used for PBKDF2 (generated client-side or server-side)

    The actual seed phrase NEVER leaves the client.
    """
    seed_verifier: str = Field(
        ...,
        min_length=32,
        max_length=64,
        description="Base64-encoded SHA-256 hash of the seed key"
    )
    seed_salt: str = Field(
        ...,
        min_length=16,
        max_length=64,
        description="Base64-encoded salt for PBKDF2 derivation"
    )


class SeedSetupResponse(BaseModel):
    """Response after successfully setting up seed recovery."""
    success: bool
    message: str


class SeedSaltRequest(BaseModel):
    """Request to get the seed salt for a user (for recovery flow)."""
    username: str = Field(..., min_length=1, max_length=50)


class SeedSaltResponse(BaseModel):
    """Response containing the seed salt for recovery."""
    seed_salt: str
    has_seed_recovery: bool


class SeedVerifyRequest(BaseModel):
    """
    Request to verify seed phrase for password recovery.

    Client sends:
    - username: The account to recover
    - seed_verifier: SHA-256 hash of re-derived seed key
    - new_password: The new password to set (pre-hashed auth key)
    - new_kdf_salt: New salt for master key derivation
    """
    username: str = Field(..., min_length=1, max_length=50)
    seed_verifier: str = Field(
        ...,
        min_length=32,
        max_length=64,
        description="Base64-encoded SHA-256 hash of the seed key"
    )
    new_password: str = Field(
        ...,
        min_length=8,
        description="New auth key (hashed) for login"
    )
    new_kdf_salt: str = Field(
        ...,
        min_length=16,
        max_length=64,
        description="New salt for client-side key derivation"
    )


class SeedVerifyResponse(BaseModel):
    """Response after seed verification attempt."""
    success: bool
    message: str


class SeedStatusResponse(BaseModel):
    """Response indicating whether user has seed recovery enabled."""
    has_seed_recovery: bool
    created_at: Optional[datetime] = None

