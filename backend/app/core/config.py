# backend/app/core/config.py
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    PROJECT_NAME: str = "Pallium"
    PROJECT_VERSION: str = "1.0.0"

    # --- THÊM DÒNG NÀY ĐỂ FIX LỖI AttributeError ---
    API_V1_STR: str = "/api/v1"

    # BẮT BUỘC PHẢI CÓ TRONG FILE .env SAU NÀY
    SECRET_KEY: str = os.getenv("SECRET_KEY", "tạm_thời_để_chuỗi_này_để_test_local_nhé_đừng_dùng_thật")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

    # Thêm cái này luôn để tránh lỗi tiếp theo ở main.py (CORS Middleware)
    BACKEND_CORS_ORIGINS: list = [
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]


settings = Settings()