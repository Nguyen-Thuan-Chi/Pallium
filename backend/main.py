# backend/main.py (Cập nhật)
from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from backend.app.api.v1.router import api_router # Import router tổng

app = FastAPI(title="Pallium API")
origins = [
    "http://127.0.0.1:5500",
    "http://localhost:5500",
]
# ... (Giữ nguyên phần CORS) ...
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Cho phép mọi nguồn (Frontend port 5500)
    allow_credentials=True,
    allow_methods=["*"], # QUAN TRỌNG: Cho phép cả POST, GET, OPTIONS...
    allow_headers=["*"],
)
# Include Router
app.include_router(api_router, prefix="/api/v1") # Prefix chung cho toàn bộ API v1

# ... (Giữ nguyên root endpoint) ...