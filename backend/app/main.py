from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from backend.app.api.v1.router import api_router
from backend.app.core.config import settings
from backend.app.db.base import Base, engine

# --- Import Models để SQLAlchemy nhận diện bảng ---
from backend.app.models import user, vault_item

# --- HÀM LIFESPAN: TẠO BẢNG KHI SERVER KHỞI ĐỘNG ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Tạo bảng (Async way)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    # Code chạy khi server tắt (nếu cần)

# --- KHỞI TẠO APP VỚI LIFESPAN ---
app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan # <--- Gắn hàm tạo bảng vào đây
)

# Set up CORS


app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(chrome-extension://nakmkbeoeoecdpgkefjomdcaciccjfna|https://pallium-vault\.vercel\.app|https://www\.pallium\.click|https://pallium\.click|http://localhost:5500|http://127\.0\.0\.1:5500)$",
    allow_credentials=False,  # 🔥 PHẢI FALSE
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/")
def root():
    return {"message": "Welcome to Pallium Secure Vault API"}