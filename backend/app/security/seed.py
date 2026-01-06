# backend/app/security/seed.py
"""
Security utilities for seed phrase verification.

This module handles:
- Verifier comparison (constant-time)
- Failed attempt tracking
- NO plaintext seed handling

The seed phrase is processed ONLY on the client.
Server only sees the verifier (hash of derived key).
"""
import secrets
import hashlib
import base64
from datetime import datetime, timezone
from typing import Optional


# Maximum failed verification attempts before lockout
MAX_FAILED_ATTEMPTS = 5

# Lockout duration in minutes
LOCKOUT_DURATION_MINUTES = 15


def generate_seed_salt() -> str:
    """
    Generate a cryptographically secure random salt for seed key derivation.

    Returns:
        Base64-encoded 16-byte (128-bit) salt
    """
    salt_bytes = secrets.token_bytes(16)
    return base64.b64encode(salt_bytes).decode('utf-8')


def constant_time_compare(a: str, b: str) -> bool:
    """
    Compare two strings in constant time to prevent timing attacks.

    Args:
        a: First string (expected verifier)
        b: Second string (provided verifier)

    Returns:
        True if strings match, False otherwise
    """
    if len(a) != len(b):
        # Still do the comparison to maintain constant time
        # but ensure we return False
        secrets.compare_digest(a, a)
        return False
    return secrets.compare_digest(a, b)


def verify_seed_key(stored_verifier: str, provided_verifier: str) -> bool:
    """
    Verify a provided seed verifier against the stored verifier.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        stored_verifier: The verifier stored in the database
        provided_verifier: The verifier provided by the client

    Returns:
        True if verifiers match, False otherwise
    """
    return constant_time_compare(stored_verifier, provided_verifier)


def is_account_locked(failed_attempts: int, last_attempt_at: Optional[datetime]) -> bool:
    """
    Check if an account is locked due to too many failed attempts.

    Args:
        failed_attempts: Number of consecutive failed attempts
        last_attempt_at: Timestamp of last attempt

    Returns:
        True if account is locked, False otherwise
    """
    if failed_attempts < MAX_FAILED_ATTEMPTS:
        return False

    if last_attempt_at is None:
        return False

    # Calculate lockout expiry
    now = datetime.now(timezone.utc)

    # Ensure last_attempt_at is timezone-aware
    if last_attempt_at.tzinfo is None:
        last_attempt_at = last_attempt_at.replace(tzinfo=timezone.utc)

    elapsed_minutes = (now - last_attempt_at).total_seconds() / 60

    return elapsed_minutes < LOCKOUT_DURATION_MINUTES


def get_lockout_remaining_minutes(last_attempt_at: Optional[datetime]) -> int:
    """
    Get remaining lockout time in minutes.

    Args:
        last_attempt_at: Timestamp of last failed attempt

    Returns:
        Remaining lockout minutes, or 0 if not locked
    """
    if last_attempt_at is None:
        return 0

    now = datetime.now(timezone.utc)

    if last_attempt_at.tzinfo is None:
        last_attempt_at = last_attempt_at.replace(tzinfo=timezone.utc)

    elapsed_minutes = (now - last_attempt_at).total_seconds() / 60
    remaining = LOCKOUT_DURATION_MINUTES - elapsed_minutes

    return max(0, int(remaining))


def validate_verifier_format(verifier: str) -> bool:
    """
    Validate that a verifier is properly formatted.

    Expected format: Base64-encoded SHA-256 hash (44 characters with padding)

    Args:
        verifier: The verifier string to validate

    Returns:
        True if format is valid, False otherwise
    """
    try:
        # Attempt to decode as base64
        decoded = base64.b64decode(verifier)
        # SHA-256 produces 32 bytes
        return len(decoded) == 32
    except Exception:
        return False


def validate_salt_format(salt: str) -> bool:
    """
    Validate that a salt is properly formatted.

    Expected format: Base64-encoded bytes (minimum 16 bytes)

    Args:
        salt: The salt string to validate

    Returns:
        True if format is valid, False otherwise
    """
    try:
        decoded = base64.b64decode(salt)
        return len(decoded) >= 16
    except Exception:
        return False

