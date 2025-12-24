# backend/app/api/v1/endpoints/vault.py
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from backend.app.api import deps
from backend.app.db.base import get_db
from backend.app.models.user import User
from backend.app.models.vault_item import VaultItem
from backend.app.schemas.vault import VaultItemCreate, VaultItemResponse, VaultItemUpdate

router = APIRouter()

# 1. LẤY TOÀN BỘ ITEM (GET)
# Logic Twin-Lock: Trả về HẾT. Client tự lọc Real/Fake.
@router.get("/", response_model=List[VaultItemResponse])
async def read_vault_items(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
    skip: int = 0,
    limit: int = 100
):
    # Chỉ lấy item của chính user đó (Where user_id == current_user.id)
    query = select(VaultItem).where(VaultItem.user_id == current_user.id).offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()

# 2. TẠO ITEM MỚI (POST)
@router.post("/", response_model=VaultItemResponse)
async def create_vault_item(
    item_in: VaultItemCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user)
):
    new_item = VaultItem(
        **item_in.model_dump(), # Unpack dữ liệu từ schema
        user_id=current_user.id # Gán chủ sở hữu là user đang login
    )
    db.add(new_item)
    await db.commit()
    await db.refresh(new_item)
    return new_item

# 3. CẬP NHẬT ITEM (PUT) - Quan trọng cho tính năng Re-encrypt
@router.put("/{item_id}", response_model=VaultItemResponse)
async def update_vault_item(
    item_id: int,
    item_in: VaultItemUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user)
):
    # Tìm item
    query = select(VaultItem).where(VaultItem.id == item_id, VaultItem.user_id == current_user.id)
    result = await db.execute(query)
    item = result.scalars().first()

    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    # Update các trường có thay đổi
    update_data = item_in.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(item, key, value)

    db.add(item)
    await db.commit()
    await db.refresh(item)
    return item

# 4. XÓA ITEM (DELETE)
@router.delete("/{item_id}")
async def delete_vault_item(
    item_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user)
):
    query = select(VaultItem).where(VaultItem.id == item_id, VaultItem.user_id == current_user.id)
    result = await db.execute(query)
    item = result.scalars().first()

    if not item:
        raise HTTPException(status_code=404, detail="Item not found")

    await db.delete(item)
    await db.commit()
    return {"message": "Item deleted successfully"}