# backend/app/api/v1/router.py
from fastapi import APIRouter
from backend.app.api.v1.endpoints import auth, vault # Thêm vault

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
# Đăng ký vault router
api_router.include_router(vault.router, prefix="/vault", tags=["vault"])