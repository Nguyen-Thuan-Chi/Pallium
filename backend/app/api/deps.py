# backend/app/api/deps.py
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.app.core.config import settings
from backend.app.db.base import get_db
from backend.app.models.user import User
# Import class vừa thêm ở Bước 1
from backend.app.schemas.user import TokenPayload

reusable_oauth2 = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login"
)


async def get_current_user(
        db: AsyncSession = Depends(get_db),
        token: str = Depends(reusable_oauth2)
) -> User:
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        token_data = TokenPayload(**payload)

        # Lấy mode từ token (nếu không có thì mặc định normal)
        login_mode = payload.get("mode", "normal")

    except (JWTError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )

    # Tìm user trong DB
    result = await db.execute(select(User).where(User.username == token_data.sub))
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # !!! GẮN CỜ VÀO USER ĐỂ DÙNG Ở VAULT.PY !!!
    user.login_mode = login_mode

    return user