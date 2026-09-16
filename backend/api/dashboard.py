from typing import Any, Dict, List
from fastapi import APIRouter
from ..database import (
    get_category_distribution,
    get_dashboard_metrics,
    get_recent_events,
    get_risk_distribution,
    get_timeline_events,
)
from ..engine.risk_engine import calculate_entity_risk, correlate_threat_events

router = APIRouter(prefix="/dashboard", tags=["Dashboard & Telemetry"])

@router.get("/metrics", response_model=Dict[str, Any])
async def read_metrics():
    """Returns high-level SOC Command metrics."""
    return get_dashboard_metrics()

@router.get("/timeline", response_model=List[Dict[str, Any]])
async def read_timeline(limit: int = 40):
    """Returns chronologically ordered events for attack timeline plotting."""
    return get_timeline_events(limit=limit)

@router.get("/distribution", response_model=Dict[str, Any])
async def read_distribution():
    """Returns category breakdown and risk severity distribution."""
    return {
        "categories": get_category_distribution(),
        "risk_levels": get_risk_distribution(),
    }

@router.get("/entities", response_model=Dict[str, Any])
async def read_high_risk_entities():
    """Returns top high-risk identities and aggressive origin IPs with time-decayed composite scores."""
    events = get_recent_events(limit=200)
    top_identities = calculate_entity_risk(events, entity_type="identity")
    top_ips = calculate_entity_risk(events, entity_type="ip")
    return {
        "top_identities": top_identities[:10],
        "top_ips": top_ips[:10],
    }

@router.get("/correlations", response_model=List[Dict[str, Any]])
async def read_correlations():
    """Detects multi-stage attack campaigns across detection engines."""
    events = get_recent_events(limit=200)
    return correlate_threat_events(events)
