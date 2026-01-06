# backend/app/api/v1/endpoints/seed.py
"""
API endpoints for seed phrase recovery.

Endpoints:
- POST /seed/setup - Set up seed recovery for authenticated user
- POST /seed/verify - Verify seed and reset password
- GET /seed/salt/{username} - Get seed salt for recovery flow
- GET /seed/status - Check if current user has seed recovery enabled

Security:
- Setup requires authentication
- Verification uses constant-time comparison
- Failed attempts are tracked with lockout
- Seed phrase NEVER touches the server
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.app.api import deps
from backend.app.db.base import get_db
from backend.app.models.user import User
from backend.app.models.seed_recovery import SeedRecovery
from backend.app.schemas.seed import (
    SeedSetupRequest,
    SeedSetupResponse,
    SeedVerifyRequest,
    SeedVerifyResponse,
    SeedSaltResponse,
    SeedStatusResponse,
)
from backend.app.security import seed as seed_security
from backend.app.security import hashing

router = APIRouter()


@router.post("/setup", response_model=SeedSetupResponse)
async def setup_seed_recovery(
    request: SeedSetupRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Set up seed phrase recovery for the authenticated user.

    The client generates a seed phrase, derives a seed_key using PBKDF2,
    then sends only the verifier (SHA-256 hash of seed_key) to the server.

    The seed phrase NEVER leaves the client.
    """
    # Validate verifier format
    if not seed_security.validate_verifier_format(request.seed_verifier):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verifier format. Expected base64-encoded SHA-256 hash."
        )

    # Validate salt format
    if not seed_security.validate_salt_format(request.seed_salt):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid salt format. Expected base64-encoded bytes (min 16 bytes)."
        )

    # Check if user already has seed recovery set up
    result = await db.execute(
        select(SeedRecovery).where(SeedRecovery.user_id == current_user.id)
    )
    existing = result.scalars().first()

    if existing:
        # Update existing seed recovery
        existing.seed_salt = request.seed_salt
        existing.seed_verifier = request.seed_verifier
        existing.is_enabled = True
        existing.failed_attempts = 0
        existing.last_attempt_at = None
        db.add(existing)
    else:
        # Create new seed recovery record
        seed_recovery = SeedRecovery(
            user_id=current_user.id,
            seed_salt=request.seed_salt,
            seed_verifier=request.seed_verifier,
            is_enabled=True
        )
        db.add(seed_recovery)

    await db.commit()

    return SeedSetupResponse(
        success=True,
        message="Seed recovery has been set up successfully."
    )


@router.get("/salt/{username}", response_model=SeedSaltResponse)
async def get_seed_salt(
    username: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Get the seed salt for a user to initiate recovery flow.

    This is a public endpoint (no auth required) since the user
    is trying to recover their password.

    Returns 404 if user doesn't exist or doesn't have seed recovery.
    """
    # Find user
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Find seed recovery record
    result = await db.execute(
        select(SeedRecovery).where(
            SeedRecovery.user_id == user.id,
            SeedRecovery.is_enabled == True
        )
    )
    seed_recovery = result.scalars().first()

    if not seed_recovery:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Seed recovery not enabled for this user"
        )

    # Check if account is locked
    if seed_security.is_account_locked(
        seed_recovery.failed_attempts,
        seed_recovery.last_attempt_at
    ):
        remaining = seed_security.get_lockout_remaining_minutes(
            seed_recovery.last_attempt_at
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account locked due to too many failed attempts. Try again in {remaining} minutes."
        )

    return SeedSaltResponse(
        seed_salt=seed_recovery.seed_salt,
        has_seed_recovery=True
    )


@router.post("/verify", response_model=SeedVerifyResponse)
async def verify_seed_and_reset_password(
    request: SeedVerifyRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Verify seed phrase and reset master password.

    The client:
    1. Gets seed_salt from /seed/salt/{username}
    2. Re-derives seed_key using PBKDF2(seed_phrase, seed_salt)
    3. Computes seed_verifier = SHA-256(seed_key)
    4. Sends verifier + new password to this endpoint

    If verification succeeds, the password is reset.

    Note: This does NOT decrypt vault data. The user must still
    have their master key or re-encrypt vault items.
    """
    # Find user
    result = await db.execute(select(User).where(User.username == request.username))
    user = result.scalars().first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Find seed recovery record
    result = await db.execute(
        select(SeedRecovery).where(
            SeedRecovery.user_id == user.id,
            SeedRecovery.is_enabled == True
        )
    )
    seed_recovery = result.scalars().first()

    if not seed_recovery:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Seed recovery not enabled for this user"
        )

    # Check if account is locked
    if seed_security.is_account_locked(
        seed_recovery.failed_attempts,
        seed_recovery.last_attempt_at
    ):
        remaining = seed_security.get_lockout_remaining_minutes(
            seed_recovery.last_attempt_at
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account locked. Try again in {remaining} minutes."
        )

    # Verify the seed key using constant-time comparison
    is_valid = seed_security.verify_seed_key(
        seed_recovery.seed_verifier,
        request.seed_verifier
    )

    if not is_valid:
        # Increment failed attempts
        seed_recovery.failed_attempts += 1
        seed_recovery.last_attempt_at = datetime.now(timezone.utc)
        db.add(seed_recovery)
        await db.commit()

        attempts_remaining = seed_security.MAX_FAILED_ATTEMPTS - seed_recovery.failed_attempts

        if attempts_remaining > 0:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid seed phrase. {attempts_remaining} attempts remaining."
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Account locked for {seed_security.LOCKOUT_DURATION_MINUTES} minutes."
            )

    # Verification successful - reset password
    user.hashed_password = hashing.get_password_hash(request.new_password)
    user.kdf_salt = request.new_kdf_salt

    # Reset failed attempts
    seed_recovery.failed_attempts = 0
    seed_recovery.last_attempt_at = None

    db.add(user)
    db.add(seed_recovery)
    await db.commit()

    return SeedVerifyResponse(
        success=True,
        message="Password reset successful. You can now log in with your new password."
    )


@router.get("/status", response_model=SeedStatusResponse)
async def get_seed_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Check if the current user has seed recovery enabled.

    Requires authentication.
    """
    result = await db.execute(
        select(SeedRecovery).where(
            SeedRecovery.user_id == current_user.id,
            SeedRecovery.is_enabled == True
        )
    )
    seed_recovery = result.scalars().first()

    if seed_recovery:
        return SeedStatusResponse(
            has_seed_recovery=True,
            created_at=seed_recovery.created_at
        )

    return SeedStatusResponse(
        has_seed_recovery=False,
        created_at=None
    )


@router.delete("/disable", response_model=SeedSetupResponse)
async def disable_seed_recovery(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Disable seed recovery for the current user.

    Requires authentication.
    """
    result = await db.execute(
        select(SeedRecovery).where(SeedRecovery.user_id == current_user.id)
    )
    seed_recovery = result.scalars().first()

    if not seed_recovery:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Seed recovery not set up for this user"
        )

    seed_recovery.is_enabled = False
    db.add(seed_recovery)
    await db.commit()

    return SeedSetupResponse(
        success=True,
        message="Seed recovery has been disabled."
    )

