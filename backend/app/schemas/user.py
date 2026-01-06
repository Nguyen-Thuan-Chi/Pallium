# backend/app/schemas/user.py
from pydantic import BaseModel
from typing import Optional

# Schema dùng khi User gửi request Đăng ký
class UserCreate(BaseModel):
    username: str
    password: str
    kdf_salt: str  # Frontend sinh ra và gửi lên

# Schema dùng khi Server trả về thông tin User (KHÔNG trả về password)
class UserResponse(BaseModel):
    id: int
    username: str
    kdf_salt: str
    is_active: bool
    is_2fa_enabled: bool = False

    class Config:
        from_attributes = True # Pydantic v2 dùng cái này thay cho orm_mode

# Schema cho Token trả về
class Token(BaseModel):
    access_token: str
    token_type: str

# --- THÊM CLASS NÀY ĐỂ FIX LỖI IMPORT Ở DEPS.PY ---
class TokenPayload(BaseModel):
    sub: Optional[str] = None
    mode: str = "normal"  # Mặc định là normal, nếu là SOS sẽ là "duress"


# ─────────────────────────────────────────────────────────────
# 2FA / TOTP Schemas
# ─────────────────────────────────────────────────────────────

class TwoFactorSetupResponse(BaseModel):
    """Response when setting up 2FA - contains QR code and secret"""
    secret: str  # Base32 secret for manual entry
    qr_code: str  # Base64-encoded PNG image
    otpauth_uri: str  # The otpauth:// URI

class TwoFactorVerifyRequest(BaseModel):
    """Request to verify and enable 2FA"""
    code: str  # 6-digit TOTP code

class TwoFactorStatusResponse(BaseModel):
    """Response for 2FA status check"""
    is_enabled: bool


# ─────────────────────────────────────────────────────────────
# Login with 2FA
# ─────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    """Login request with optional TOTP code"""
    username: str
    password: str
    totp_code: Optional[str] = None  # Required if 2FA enabled

class LoginResponse(BaseModel):
    """Login response - may require 2FA"""
    access_token: Optional[str] = None
    token_type: str = "bearer"
    requires_2fa: bool = False


# ─────────────────────────────────────────────────────────────
# Duress / SOS Password Schemas
# ─────────────────────────────────────────────────────────────

class DuressPasswordSet(BaseModel):
    """Request to set duress password"""
    duress_password: str  # The SOS/duress password

class DuressPasswordStatus(BaseModel):
    """Response for duress password status"""
    is_set: bool
