# backend/app/core/config.py
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    PROJECT_NAME: str = "Pallium"
    PROJECT_VERSION: str = "1.0.0"

    # BẮT BUỘC PHẢI CÓ TRONG FILE .env SAU NÀY
    # Generate bằng lệnh: openssl rand -hex 32
    SECRET_KEY: str = os.getenv("SECRET_KEY", "tạm_thời_để_chuỗi_này_để_test_local_nhé_đừng_dùng_thật")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))


settings = Settings()