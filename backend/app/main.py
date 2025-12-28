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
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://pallium-vault.vercel.app/",
                   "https://pallium-vault.vercel.app",
                   "https://www.pallium.click",
                   "https://www.pallium.click/",
                   "https://pallium.click",  # Đề phòng user không gõ www
                   "https://pallium.click/"
                   "chrome-extension://nakmkbeoeoecdpgkefjomdcaciccjfna"
                   ],  # Cho phép tất cả các nguồn (Localhost, Render, Vercel...) https://pallium-frontend.vercel.app
    allow_credentials=True,
    allow_methods=["*"],  # Cho phép tất cả các method (GET, POST, PUT, DELETE...)
    allow_headers=["*"],  # Cho phép tất cả các header
)
app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/")
def root():
    return {"message": "Welcome to Pallium Secure Vault API"}