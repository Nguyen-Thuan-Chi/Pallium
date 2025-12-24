# backend/app/db/base.py
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

# Đường dẫn DB. Lưu ý: 3 dấu gạch chéo /// là đường dẫn tương đối
DATABASE_URL = "sqlite+aiosqlite:///./pallium.db"

# Tạo Engine Async
engine = create_async_engine(
    DATABASE_URL,
    echo=True, # Bật log SQL để debug (tắt khi deploy production)
    future=True
)

# Tạo Session Factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False
)

# Class cha cho các Model
class Base(DeclarativeBase):
    pass

# Hàm Dependency để lấy DB session (Dùng trong API)
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session