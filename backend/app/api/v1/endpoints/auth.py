from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete  # <--- THÊM 'delete' VÀO ĐÂY
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta

from backend.app.db.base import get_db
from backend.app.models.user import User
from backend.app.schemas.user import UserCreate, UserResponse, Token
from backend.app.security import hashing, jwt
from backend.app.core.config import settings
from pydantic import BaseModel
# Import Model Item để xóa
from backend.app.models.vault_item import VaultItem as Item

router = APIRouter()


@router.post("/register", response_model=UserResponse)
async def register(user_in: UserCreate, db: AsyncSession = Depends(get_db)):
    # 1. Check user tồn tại chưa
    result = await db.execute(select(User).where(User.username == user_in.username))
    existing_user = result.scalars().first()
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    # 2. Tạo user mới
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
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    # 1. Tìm user
    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalars().first()

    # Biến cờ để xác định xem có cho đăng nhập không
    is_authenticated = False

    # 2. LOGIC KIỂM TRA MẬT KHẨU
    if user:
        # CASE A: Mật khẩu đúng -> Login bình thường
        if hashing.verify_password(form_data.password, user.hashed_password):
            is_authenticated = True

        # CASE B: Mật khẩu Duress (Kết thúc bằng "SOS") -> XÓA SẠCH DATA + Login giả
        elif form_data.password.endswith("SOS"):
            real_password = form_data.password[:-3]  # Cắt 3 ký tự cuối (SOS)

            # Check xem phần đầu có phải pass thật không
            if hashing.verify_password(real_password, user.hashed_password):
                print(f"⚠️ DURESS LOGIN DETECTED FOR: {user.username}. WIPING VAULT...")

                # --- THỰC HIỆN TIÊU THỔ (Xóa hết Item của user này) ---
                # Lưu ý: Giả sử trong model Item có trường owner_id
                await db.execute(delete(Item).where(Item.user_id == user.id))
                await db.commit()

                # Vẫn set thành True để cho nó login vào (đánh lừa kẻ địch)
                is_authenticated = True

    # 3. Nếu không phải cả 2 trường hợp trên -> Lỗi 401
    if not is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Tạo JWT (Cho cả User thật và User đang bị cưỡng ép)
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = jwt.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


class SaltResponse(BaseModel):
    salt: str


@router.get("/salt/{username}", response_model=SaltResponse)
async def get_user_salt(username: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {"salt": user.kdf_salt}