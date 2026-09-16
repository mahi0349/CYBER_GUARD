from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from ..database import get_event_by_id, get_recent_events, save_threat_event
from ..models.schemas import ThreatDetectionResult

router = APIRouter(prefix="/events", tags=["Events"])

@router.get("", response_model=List[Dict[str, Any]])
async def list_events(limit: int = 50):
    return get_recent_events(limit=limit)

@router.get("/{event_id}", response_model=Dict[str, Any])
async def get_event(event_id: str):
    event = get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Threat event not found")
    return event
