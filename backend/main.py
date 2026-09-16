from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api.events import router as events_router
from .api.health import router as health_router
from .api.phishing import router as phishing_router
from .api.deepfake import router as deepfake_router
from .api.account import router as account_router
from .config import API_DESCRIPTION, API_TITLE, API_VERSION, CORS_ORIGINS
from .database import init_db

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database on startup
    init_db()
    print("[OK] CYBERGUARD Threat Database initialized.")
    yield
    print("[OK] CYBERGUARD Threat Engine shut down gracefully.")

app = FastAPI(
    title=API_TITLE,
    description=API_DESCRIPTION,
    version=API_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(health_router, prefix="/api")
app.include_router(events_router, prefix="/api")
app.include_router(phishing_router, prefix="/api")
app.include_router(deepfake_router, prefix="/api")
app.include_router(account_router, prefix="/api")

@app.get("/")
async def root():
    return {
        "system": API_TITLE,
        "version": API_VERSION,
        "status": "OPERATIONAL",
        "docs_url": "/docs",
        "health_check": "/api/health",
        "message": "CYBERGUARD AI Cyber Threat Detection and Response Platform is active."
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
