from fastapi import APIRouter
from app.routes.health import router as health_router
from app.routes.analyze import router as analyze_router
from app.routes.investigate import router as investigate_router
from app.routes.incidents import router as incidents_router
from app.routes.uipath import router as uipath_router
from app.routes.dashboard import router as dashboard_router
from app.routes.threat_intel import router as threat_intel_router

api_router = APIRouter()

api_router.include_router(health_router)
api_router.include_router(analyze_router)
api_router.include_router(investigate_router)
api_router.include_router(incidents_router)
api_router.include_router(uipath_router)
api_router.include_router(dashboard_router)
api_router.include_router(threat_intel_router)

__all__ = ["api_router"]
