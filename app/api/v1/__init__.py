"""
app/api/v1/__init__.py
Registers all v1 endpoint routers onto a single APIRouter.
"""
from fastapi import APIRouter

from app.api.v1.endpoints.assets import router as assets_router
from app.api.v1.endpoints.auth import router as auth_router
from app.api.v1.endpoints.dashboard import router as dashboard_router
from app.api.v1.endpoints.findings import router as findings_router
from app.api.v1.endpoints.reports import router as reports_router
from app.api.v1.endpoints.scans import router as scans_router
from app.api.v1.endpoints.settings import router as settings_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth_router)
api_router.include_router(assets_router)
api_router.include_router(findings_router)
api_router.include_router(scans_router)
api_router.include_router(dashboard_router)
api_router.include_router(reports_router)
api_router.include_router(settings_router)
