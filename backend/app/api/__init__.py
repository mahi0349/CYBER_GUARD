from app.api.auth import router as auth_router
from app.api.dashboard import router as dashboard_router
from app.api.threats import router as threats_router
from app.api.incidents import router as incidents_router
from app.api.analyze import router as analyze_router

__all__ = [
    "auth_router",
    "dashboard_router",
    "threats_router",
    "incidents_router",
    "analyze_router",
]
