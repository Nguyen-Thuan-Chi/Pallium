import asyncio
from backend.app.db.base import engine, Base
# Import models để engine nhận diện được metadata
from backend.app.models import User, VaultItem

async def init_models():
    async with engine.begin() as conn:
        # Xóa bảng cũ (nếu có) và tạo mới - DEV MODE ONLY
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    print(">>> Tables Created Successfully!")

if __name__ == "__main__":
    asyncio.run(init_models())