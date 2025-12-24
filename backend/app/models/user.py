# backend/app/models/user.py
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.sql import func
from backend.app.db.base import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)

    # Password này chỉ để login! Không dùng để decrypt data!
    hashed_password = Column(String(255), nullable=False)

    # Salt dùng cho KDF ở phía Client (để sinh key giải mã)
    # Client cần cái này trước khi login
    # kdf_salt: base64-encoded bytes

    kdf_salt = Column(String(64), nullable=False)

    is_active = Column(Boolean, nullable=False, default=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())