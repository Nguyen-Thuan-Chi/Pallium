# backend/app/schemas/vault.py
from pydantic import BaseModel
from datetime import datetime
from typing import Optional


# Base class chứa các trường chung
class VaultItemBase(BaseModel):
    label: str
    risk_level: int = 1  # Mặc định là Low Risk

    # Dữ liệu mã hóa (Client làm hết, server chỉ lưu chuỗi này)
    encrypted_data: str
    iv: str  # Initialization Vector (Bắt buộc để giải mã)
    auth_tag: Optional[str] = None


# Schema dùng khi TẠO mới (Client gửi lên)
class VaultItemCreate(VaultItemBase):
    pass


# Schema dùng khi CẬP NHẬT (Client gửi lên)
class VaultItemUpdate(BaseModel):
    label: Optional[str] = None
    risk_level: Optional[int] = None
    encrypted_data: Optional[str] = None
    iv: Optional[str] = None
    auth_tag: Optional[str] = None


# Schema trả về cho Client (Server trả về)
class VaultItemResponse(VaultItemBase):
    id: int
    user_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True