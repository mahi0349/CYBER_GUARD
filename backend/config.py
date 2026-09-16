import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATABASE_PATH = BASE_DIR / "cyberguard.db"

DATA_DIR.mkdir(parents=True, exist_ok=True)

# App configuration
API_TITLE = "CYBERGUARD AI Cyber Defence Platform"
API_VERSION = "1.0.0"
API_DESCRIPTION = (
    "AI-Powered Cyber Threat, Phishing & Digital Impersonation Detection and Response System"
)

CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "*",
]
