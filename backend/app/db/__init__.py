import asyncio
import logging
import sys
import os
from pathlib import Path

# --- HACK PATH: Tự động tìm thư mục gốc để import không bị lỗi ---
# Tìm đường dẫn đến thư mục chứa folder 'backend'
current_file = Path(__file__).resolve()
project_root = current_file.parents[3]  # Lùi lại 3 cấp từ db/init_db.py
sys.path.append(str(project_root))
# ----------------------------------------------------------------

from backend.app.db.session import engine
from backend.app.db.base import Base

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def init_models():
    try:
        async with engine.begin() as conn:
            # Xóa comment dòng dưới nếu muốn reset sạch DB (CẨN THẬN)
            # await conn.run_sync(Base.metadata.drop_all)

            logger.info("⏳ Dang ket noi Database de tao bang...")
            await conn.run_sync(Base.metadata.create_all)
            logger.info("✅ SUCCESS! Da tao bang thanh cong.")
    except Exception as e:
        logger.error(f"❌ LOI ROI: {e}")
        raise


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(init_models())