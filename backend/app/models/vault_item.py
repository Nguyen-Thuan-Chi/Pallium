# backend/app/models/vault_item.py
from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime
from sqlalchemy.sql import func
from backend.app.db.base import Base


class VaultItem(Base):
    __tablename__ = "vault_items"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    # --- METADATA (Server ĐƯỢC PHÉP nhìn thấy) ---
    # Risk Level: 1 (Low), 2 (Medium), 3 (High)
    # Dùng để áp dụng Policy (timeout, re-auth)
    risk_level = Column(Integer, default=1, nullable=False)

    # Label hiển thị trên UI (Ví dụ: "Facebook", "Bank ABC")
    # Có thể mã hóa nốt nếu muốn Paranoid, nhưng để plain cho dễ tìm kiếm demo
    label = Column(String(100), nullable=False)

    # --- SECRET DATA (Server MÙ - Encrypted Blob) ---
    # Chứa JSON: {username, password, notes, otp_secret...}
    # Đã được mã hóa client-side bằng Key của User.
    encrypted_data = Column(Text, nullable=False)

    # iv: base64-encoded (12 bytes for AES-GCM)
    iv = Column(String(32), nullable=False)

    # auth_tag: base64-encoded (16 bytes)
    auth_tag = Column(String(32), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )

    # --- LOGIC TWIN-LOCK (FAKE vs REAL) ---
    # Làm sao phân biệt Item thật và Item fake (Duress)?
    # Cách đơn giản nhất cho sinh viên:
    # Client tự quy định. Server không cần cột "is_fake".
    # Server trả về HẾT. Client dùng Key Thật giải mã -> ra đồ thật.
    # Client dùng Key Giả giải mã -> ra đồ giả.
    # -> Vậy nên schema KHÔNG CẦN thay đổi. Sự kỳ diệu nằm ở encrypted_data.