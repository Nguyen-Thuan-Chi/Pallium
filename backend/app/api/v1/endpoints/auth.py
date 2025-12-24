# backend/app/api/v1/endpoints/auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta

from backend.app.db.base import get_db
from backend.app.models.user import User
from backend.app.schemas.user import UserCreate, UserResponse, Token
from backend.app.security import hashing, jwt
from backend.app.core.config import settings
from pydantic import BaseModel

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
        kdf_salt=user_in.kdf_salt  # Lưu salt từ frontend gửi lên
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user


@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    # OAuth2PasswordRequestForm tự lấy username/password từ form-data

    # 1. Tìm user
    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalars().first()

    # 2. Verify mật khẩu
    if not user or not hashing.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Tạo JWT
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = jwt.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    # 4. Trả về token + set cookie (Cái cookie mình sẽ làm kỹ ở bước sau, giờ test API raw trước)
    return {"access_token": access_token, "token_type": "bearer"}


class SaltResponse(BaseModel):
    salt: str


@router.get("/salt/{username}", response_model=SaltResponse)
async def get_user_salt(username: str, db: AsyncSession = Depends(get_db)):
    # 1. Tìm user
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalars().first()

    # 2. Nếu không thấy user -> Trả về muối giả (Fake Salt) để chống user enumeration attack
    # (Kẻ tấn công không biết user tồn tại hay không vì luôn nhận được salt)
    if not user:
        # Trả về một chuỗi ngẫu nhiên cố định hoặc random (tùy policy)
        # Ở đây trả về lỗi 404 cho đồ án sinh viên dễ debug,
        # còn PRO thì trả fake salt.
        raise HTTPException(status_code=404, detail="User not found")

    return {"salt": user.kdf_salt}