# backend/app/api/v1/endpoints/auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from typing import Optional
from backend.app.security import totp

from backend.app.db.base import get_db
from backend.app.models.user import User
from backend.app.schemas.user import (
    UserCreate, UserResponse, Token,
    TwoFactorSetupResponse, TwoFactorVerifyRequest, TwoFactorStatusResponse,
    LoginRequest, LoginResponse,
    DuressPasswordSet, DuressPasswordStatus
)
from backend.app.security import hashing, jwt, totp
from backend.app.core.config import settings
from backend.app.api import deps
from pydantic import BaseModel

router = APIRouter()


# ─────────────────────────────────────────────────────────────
# Internal SOS Event Logging (simple in-memory for demo)
# In production, use a proper logging/alerting system
# ─────────────────────────────────────────────────────────────
_sos_events = []

def log_sos_event(username: str, event_type: str = "duress_login"):
    """Record an SOS/duress event internally"""
    from datetime import datetime, timezone
    event = {
        "username": username,
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    _sos_events.append(event)
    # In production: send to monitoring, trigger alerts, etc.
    print(f"🚨 SOS EVENT: {event}")


@router.post("/register", response_model=UserResponse)
async def register(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == user_in.username))
    existing_user = result.scalars().first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    new_user = User(
        username=user_in.username,
        hashed_password=hashing.get_password_hash(user_in.password),
        kdf_salt=user_in.kdf_salt
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    totp_code: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Login endpoint with 2FA and duress password support.

    Flow:
    1. Check username exists
    2. Check if duress password matches -> duress mode
    3. Check if normal password matches -> normal mode
    4. If 2FA enabled, require valid TOTP code
    5. Return JWT token with mode embedded
    """
    # 1. Find user
    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalars().first()

    token_mode = "normal"
    is_authenticated = False

    if user:
        # CASE A: Check duress password FIRST (if set)
        if user.hashed_duress_password:
            if hashing.verify_password(form_data.password, user.hashed_duress_password):
                is_authenticated = True
                token_mode = "duress"
                # Log SOS event internally
                log_sos_event(user.username, "duress_login")

        # CASE B: Check normal password
        if not is_authenticated:
            if hashing.verify_password(form_data.password, user.hashed_password):
                is_authenticated = True
                token_mode = "normal"

    if not is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Check 2FA if enabled (skip for duress login - don't tip off attacker)
    if token_mode == "normal" and user.is_2fa_enabled:
        if not totp_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="2FA code required",
                headers={"X-Requires-2FA": "true"},
            )
        if not totp.verify_totp(user.totp_secret, totp_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 2FA code",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # 3. Create JWT with mode flag
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = jwt.create_access_token(
        data={"sub": user.username, "mode": token_mode},
        expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


# ─────────────────────────────────────────────────────────────
# Alternative JSON login (for frontend convenience)
# ─────────────────────────────────────────────────────────────

@router.post("/login/json", response_model=LoginResponse)
async def login_json(
    login_data: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    JSON-based login with 2FA support.
    Returns requires_2fa: true if 2FA is needed but no code provided.
    """
    result = await db.execute(select(User).where(User.username == login_data.username))
    user = result.scalars().first()

    token_mode = "normal"
    is_authenticated = False

    if user:
        # Check duress password first
        if user.hashed_duress_password:
            if hashing.verify_password(login_data.password, user.hashed_duress_password):
                is_authenticated = True
                token_mode = "duress"
                log_sos_event(user.username, "duress_login")

        # Check normal password
        if not is_authenticated:
            if hashing.verify_password(login_data.password, user.hashed_password):
                is_authenticated = True
                token_mode = "normal"

    if not is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    # Check if 2FA required (only for normal login)
    if token_mode == "normal" and user.is_2fa_enabled:
        if not login_data.totp_code:
            return LoginResponse(requires_2fa=True)
        if not totp.verify_totp(user.totp_secret, login_data.totp_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 2FA code",
            )

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = jwt.create_access_token(
        data={"sub": user.username, "mode": token_mode},
        expires_delta=access_token_expires
    )

    return LoginResponse(access_token=access_token, token_type="bearer", requires_2fa=False)


class SaltResponse(BaseModel):
    salt: str
    is_2fa_enabled: bool = False


@router.get("/salt/{username}", response_model=SaltResponse)
async def get_user_salt(username: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"salt": user.kdf_salt, "is_2fa_enabled": user.is_2fa_enabled}


# ─────────────────────────────────────────────────────────────
# 2FA / TOTP Endpoints
# ─────────────────────────────────────────────────────────────
class TwoFactorSetupResponse(BaseModel):
    secret: str
    qr_code: str
    otpauth_uri: str

class TwoFactorVerifyRequest(BaseModel):
    code: str

class TwoFactorStatusResponse(BaseModel):
    is_enabled: bool


@router.post("/2fa/setup", response_model=TwoFactorSetupResponse)
async def setup_2fa(
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(deps.get_current_user)
):
    secret = totp.generate_totp_secret()
    qr_code = totp.generate_qr_code_base64(secret, current_user.username)
    otpauth_uri = totp.get_totp_uri(secret, current_user.username)

    current_user.totp_secret = secret
    current_user.is_2fa_enabled = False
    db.add(current_user)
    await db.commit()

    return TwoFactorSetupResponse(
        secret=secret,
        qr_code=qr_code,
        otpauth_uri=otpauth_uri
    )


@router.post("/2fa/verify", response_model=TwoFactorStatusResponse)
async def verify_and_enable_2fa(
        verify_data: TwoFactorVerifyRequest,
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(deps.get_current_user)
):
    if not current_user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA setup not initiated"
        )

    if not totp.verify_totp(current_user.totp_secret, verify_data.code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid verification code"
        )

    current_user.is_2fa_enabled = True
    db.add(current_user)
    await db.commit()

    return TwoFactorStatusResponse(is_enabled=True)


@router.delete("/2fa/disable", response_model=TwoFactorStatusResponse)
async def disable_2fa(
    verify_data: TwoFactorVerifyRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Disable 2FA. Requires a valid TOTP code for security.
    """
    if not current_user.is_2fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled."
        )

    if not totp.verify_totp(current_user.totp_secret, verify_data.code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid verification code."
        )

    # Disable 2FA and clear secret
    current_user.is_2fa_enabled = False
    current_user.totp_secret = None
    db.add(current_user)
    await db.commit()

    return TwoFactorStatusResponse(is_enabled=False)


@router.get("/2fa/status", response_model=TwoFactorStatusResponse)
async def get_2fa_status(
    current_user: User = Depends(deps.get_current_user)
):
    """Check if 2FA is enabled for the current user."""
    return TwoFactorStatusResponse(is_enabled=current_user.is_2fa_enabled)


# ─────────────────────────────────────────────────────────────
# Duress / SOS Password Endpoints
# ─────────────────────────────────────────────────────────────

@router.post("/duress/set", response_model=DuressPasswordStatus)
async def set_duress_password(
    duress_data: DuressPasswordSet,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Set or update the duress (SOS) password.

    When logged in with this password:
    - Login succeeds
    - Vault shows limited/low-risk data only
    - An SOS event is logged internally
    """
    if len(duress_data.duress_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Duress password must be at least 8 characters."
        )

    # Hash and store the duress password
    current_user.hashed_duress_password = hashing.get_password_hash(duress_data.duress_password)
    db.add(current_user)
    await db.commit()

    return DuressPasswordStatus(is_set=True)


@router.delete("/duress/remove", response_model=DuressPasswordStatus)
async def remove_duress_password(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """Remove the duress password."""
    current_user.hashed_duress_password = None
    db.add(current_user)
    await db.commit()

    return DuressPasswordStatus(is_set=False)


@router.get("/duress/status", response_model=DuressPasswordStatus)
async def get_duress_status(
    current_user: User = Depends(deps.get_current_user)
):
    """Check if a duress password is set."""
    return DuressPasswordStatus(is_set=current_user.hashed_duress_password is not None)
