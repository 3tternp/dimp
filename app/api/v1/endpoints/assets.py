"""
app/api/v1/endpoints/assets.py
CRUD for monitored assets, brand keywords, and allowed domains.
"""
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select

from app.api.deps import AnalystOrAdmin, CurrentUser, DB, Pagination
from app.models import AllowedDomain, BrandKeyword, MonitoredAsset
from app.schemas import (
    AllowedDomainCreate,
    AllowedDomainResponse,
    AssetCreate,
    AssetResponse,
    AssetUpdate,
    KeywordCreate,
    KeywordResponse,
)

router = APIRouter(prefix="/assets", tags=["assets"])


# ── Monitored assets ─────────────────────────────────────────────────────────

@router.get("", response_model=list[AssetResponse])
async def list_assets(db: DB, current_user: CurrentUser, page: Pagination):
    result = await db.execute(
        select(MonitoredAsset).order_by(MonitoredAsset.created_at.desc())
        .offset(page["skip"]).limit(page["limit"])
    )
    return result.scalars().all()


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(body: AssetCreate, db: DB, current_user: AnalystOrAdmin):
    # prevent duplicate domains
    existing = await db.execute(select(MonitoredAsset).where(MonitoredAsset.domain == body.domain))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Domain '{body.domain}' is already monitored.")

    asset = MonitoredAsset(**body.model_dump())
    db.add(asset)
    await db.flush()
    return asset


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(asset_id: UUID, db: DB, current_user: CurrentUser):
    result = await db.execute(select(MonitoredAsset).where(MonitoredAsset.id == str(asset_id)))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.patch("/{asset_id}", response_model=AssetResponse)
async def update_asset(asset_id: UUID, body: AssetUpdate, db: DB, current_user: AnalystOrAdmin):
    result = await db.execute(select(MonitoredAsset).where(MonitoredAsset.id == str(asset_id)))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    for field, value in body.model_dump(exclude_none=True).items():
        setattr(asset, field, value)
    db.add(asset)
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(asset_id: UUID, db: DB, current_user: AnalystOrAdmin):
    result = await db.execute(select(MonitoredAsset).where(MonitoredAsset.id == str(asset_id)))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    await db.delete(asset)


# ── Brand keywords ────────────────────────────────────────────────────────────

@router.get("/{asset_id}/keywords", response_model=list[KeywordResponse])
async def list_keywords(asset_id: UUID, db: DB, current_user: CurrentUser):
    result = await db.execute(
        select(BrandKeyword).where(BrandKeyword.asset_id == str(asset_id))
    )
    return result.scalars().all()


@router.post("/{asset_id}/keywords", response_model=KeywordResponse, status_code=status.HTTP_201_CREATED)
async def add_keyword(asset_id: UUID, body: KeywordCreate, db: DB, current_user: AnalystOrAdmin):
    kw = BrandKeyword(asset_id=str(asset_id), keyword=body.keyword.lower().strip())
    db.add(kw)
    await db.flush()
    return kw


@router.delete("/{asset_id}/keywords/{keyword_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_keyword(asset_id: UUID, keyword_id: UUID, db: DB, current_user: AnalystOrAdmin):
    result = await db.execute(
        select(BrandKeyword).where(
            BrandKeyword.id == str(keyword_id),
            BrandKeyword.asset_id == str(asset_id),
        )
    )
    kw = result.scalar_one_or_none()
    if not kw:
        raise HTTPException(status_code=404, detail="Keyword not found")
    await db.delete(kw)


# ── Allowed domains (allowlist) ───────────────────────────────────────────────

@router.get("/{asset_id}/allowlist", response_model=list[AllowedDomainResponse])
async def list_allowlist(asset_id: UUID, db: DB, current_user: CurrentUser):
    result = await db.execute(
        select(AllowedDomain).where(AllowedDomain.asset_id == str(asset_id))
    )
    return result.scalars().all()


@router.post("/{asset_id}/allowlist", response_model=AllowedDomainResponse, status_code=status.HTTP_201_CREATED)
async def add_allowlist_domain(asset_id: UUID, body: AllowedDomainCreate, db: DB, current_user: AnalystOrAdmin):
    entry = AllowedDomain(
        asset_id=str(asset_id),
        domain=body.domain.strip().lower(),
        reason=body.reason,
    )
    db.add(entry)
    await db.flush()
    return entry


@router.delete("/{asset_id}/allowlist/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_allowlist_domain(asset_id: UUID, entry_id: UUID, db: DB, current_user: AnalystOrAdmin):
    result = await db.execute(
        select(AllowedDomain).where(
            AllowedDomain.id == str(entry_id),
            AllowedDomain.asset_id == str(asset_id),
        )
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Allowlist entry not found")
    await db.delete(entry)
