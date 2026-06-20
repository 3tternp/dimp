"""
app/api/v1/endpoints/settings.py
Settings endpoints — user management, password change, platform info.
"""
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select

from app.api.deps import AdminUser, CurrentUser, DB, Pagination
from app.core.security import hash_password, verify_password
from app.models import User, UserRole
from app.schemas import UserCreate, UserResponse, UserUpdate

router = APIRouter(prefix="/settings", tags=["settings"])


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


class PlatformInfo(BaseModel):
    app_name: str
    app_version: str
    threat_feeds: list[str]
    scan_features: list[str]


@router.get("/profile", response_model=UserResponse)
async def get_profile(current_user: CurrentUser):
    return current_user


@router.patch("/profile", response_model=UserResponse)
async def update_profile(
    body: UserUpdate,
    db: DB,
    current_user: CurrentUser,
):
    if body.full_name is not None:
        current_user.full_name = body.full_name
    db.add(current_user)
    return current_user


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: PasswordChange,
    db: DB,
    current_user: CurrentUser,
):
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    current_user.hashed_password = hash_password(body.new_password)
    db.add(current_user)


@router.get("/users", response_model=list[UserResponse])
async def list_users(db: DB, current_user: AdminUser, page: Pagination):
    result = await db.execute(
        select(User).order_by(User.created_at.desc())
        .offset(page["skip"]).limit(page["limit"])
    )
    return result.scalars().all()


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(body: UserCreate, db: DB, current_user: AdminUser):
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(
        email=body.email,
        full_name=body.full_name,
        hashed_password=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    await db.flush()
    return user


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(user_id: UUID, body: UserUpdate, db: DB, current_user: AdminUser):
    result = await db.execute(select(User).where(User.id == str(user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    db.add(user)
    return user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: UUID, db: DB, current_user: AdminUser):
    result = await db.execute(select(User).where(User.id == str(user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if str(user.id) == str(current_user.id):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    await db.delete(user)


@router.get("/platform", response_model=PlatformInfo)
async def get_platform_info(current_user: CurrentUser):
    from app.core.config import settings
    return PlatformInfo(
        app_name=settings.app_name,
        app_version=settings.app_version,
        threat_feeds=["OpenPhish", "PhishTank", "ThreatFox", "URLhaus", "urlscan.io", "VirusTotal"],
        scan_features=["DNS", "WHOIS", "SSL", "HTTP metadata", "Login form detection",
                       "Similarity engine", "Risk scoring"],
    )
