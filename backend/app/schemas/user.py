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