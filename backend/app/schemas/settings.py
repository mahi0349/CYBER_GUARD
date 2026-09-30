from typing import Optional, Dict
from pydantic import BaseModel, Field

class PolicyUpdateRequest(BaseModel):
    low_threshold: int = Field(..., ge=0, le=100, description="Score cutoff for Low severity")
    medium_threshold: int = Field(..., ge=0, le=100, description="Score cutoff for Medium severity")
    high_threshold: int = Field(..., ge=0, le=100, description="Score cutoff for High severity")
    critical_threshold: int = Field(..., ge=0, le=100, description="Score cutoff for Critical severity")
    gemini_model: Optional[str] = Field(None, description="Active Gemini model name")

class DatabaseCounts(BaseModel):
    threats: int = 0
    incidents: int = 0
    scans: int = 0
    users: int = 0

class DatabaseStatusResponse(BaseModel):
    configured_driver: str
    active_driver: str
    active_url: str
    status: str
    is_postgres: bool
    postgres_container_running: bool
    fallback_in_use: bool
    counts: DatabaseCounts

class PolicyResponse(BaseModel):
    low_threshold: int
    medium_threshold: int
    high_threshold: int
    critical_threshold: int
    gemini_model: str
    updated_at: Optional[str] = None
    database: Optional[DatabaseStatusResponse] = None
