# backend/app/schemas/vault.py
from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class VaultItemCreate(BaseModel):
    label: str
    encrypted_data: str
    iv: str
    auth_tag: Optional[str] = None
    # risk_level MUST be an integer coming from frontend
    risk_level: int = 1

class VaultItemUpdate(BaseModel):
    label: Optional[str] = None
    encrypted_data: Optional[str] = None
    iv: Optional[str] = None
    auth_tag: Optional[str] = None
    risk_level: Optional[int] = None

class VaultItemResponse(BaseModel):
    id: int
    user_id: int
    label: str
    encrypted_data: str
    iv: str
    auth_tag: Optional[str]
    # risk_level MUST be returned as integer to frontend
    risk_level: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True