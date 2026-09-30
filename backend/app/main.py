from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

from app.config import settings
from app.models.database import Base, engine
from app.seed import seed_database

# Routers
from app.api.auth import router as auth_router
from app.api.dashboard import router as dashboard_router
from app.api.threats import router as threats_router
from app.api.incidents import router as incidents_router
from app.api.analyze import router as analyze_router
from app.api.settings import router as settings_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("cyberguard.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure tables and seed initial data
    logger.info("Initializing CYBERGUARD Threat Orchestration Platform...")
    try:
        Base.metadata.create_all(bind=engine)
        seed_database()
        
        # Synchronize risk policy thresholds from persistent storage
        from app.models.database import SessionLocal
        from app.models.settings import SystemPolicy
        with SessionLocal() as db:
            policy = db.query(SystemPolicy).first()
            if policy:
                settings.RISK_THRESHOLD_LOW = policy.low_threshold
                settings.RISK_THRESHOLD_MEDIUM = policy.medium_threshold
                settings.RISK_THRESHOLD_HIGH = policy.high_threshold
                settings.RISK_THRESHOLD_CRITICAL = policy.critical_threshold
                logger.info(
                    f"Synchronized Risk Engine policy thresholds: "
                    f"Low={policy.low_threshold}, Med={policy.medium_threshold}, "
                    f"High={policy.high_threshold}, Crit={policy.critical_threshold}"
                )
        logger.info("Database schemas and seed data verified.")
    except Exception as e:
        logger.error(f"Error during database initialization: {e}")
    yield
    # Shutdown
    logger.info("Shutting down CYBERGUARD platform.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Enterprise AI Cyber Threat Detection & Automated Response Platform",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers under /api/v1
api_prefix = settings.API_V1_STR
app.include_router(auth_router, prefix=api_prefix)
app.include_router(dashboard_router, prefix=api_prefix)
app.include_router(threats_router, prefix=api_prefix)
app.include_router(incidents_router, prefix=api_prefix)
app.include_router(analyze_router, prefix=api_prefix)
app.include_router(settings_router, prefix=api_prefix)


@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT
    }

@app.get("/", tags=["Root"])
def root():
    return {
        "platform": "CYBERGUARD AI Cyber Threat Detection & Response Platform",
        "docs_url": "/docs",
        "version": settings.VERSION,
        "status": "online"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
