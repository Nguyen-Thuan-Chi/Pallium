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
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    # 1. Tìm user
    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalars().first()

    token_mode = "normal"
    is_authenticated = False

    if user:
        # CASE A: Pass thật -> Login FULL QUYỀN
        if hashing.verify_password(form_data.password, user.hashed_password):
            is_authenticated = True
            token_mode = "normal"

        # CASE B: Pass SOS -> Login QUYỀN HẠN CHẾ (Chỉ hiện Low Risk)
        elif form_data.password.endswith("SOS"):
            real_password = form_data.password[:-3]
            if hashing.verify_password(real_password, user.hashed_password):
                print(f"⚠️ DURESS LOGIN: {user.username}. HIDING MEDIUM/HIGH RISK DATA.")
                is_authenticated = True
                token_mode = "duress"

    if not is_authenticated:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Tạo JWT có gắn cờ "mode"
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = jwt.create_access_token(
        data={"sub": user.username, "mode": token_mode},
        expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


class SaltResponse(BaseModel):
    salt: str


@router.get("/salt/{username}", response_model=SaltResponse)
async def get_user_salt(username: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalars().first()
    if not user:
        # Trả về 404 hoặc fake salt tùy ý, ở đây để 404 cho dễ debug
        raise HTTPException(status_code=404, detail="User not found")
    return {"salt": user.kdf_salt}