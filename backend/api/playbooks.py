from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..database import (
    get_actions_for_event,
    get_all_remediation_actions,
    get_event_by_id,
    save_remediation_action,
    update_incident_status,
)
from ..engine.response_engine import PLAYBOOK_CATALOG, execute_simulated_action

router = APIRouter(prefix="/playbooks", tags=["Response Playbooks & Containment"])

class PlaybookExecutionRequest(BaseModel):
    event_id: str
    action_key: str
    operator: str = "SOC Analyst / Playbook Engine"
    notes: Optional[str] = None

class StatusUpdateRequest(BaseModel):
    event_id: str
    status: str

@router.get("/catalog", response_model=Dict[str, Any])
async def get_playbook_catalog():
    """Returns the catalog of available containment playbooks."""
    return PLAYBOOK_CATALOG

@router.post("/execute", response_model=Dict[str, Any])
async def run_playbook(request: PlaybookExecutionRequest):
    """Executes a simulated containment action for a threat event and records the audit log."""
    event = get_event_by_id(request.event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Threat event not found")

    action_record = execute_simulated_action(
        event=event,
        action_key=request.action_key,
        operator=request.operator,
        notes=request.notes
    )

    save_remediation_action(action_record)
    return {
        "message": "Playbook action executed successfully",
        "action": action_record,
        "new_incident_status": "Mitigated"
    }

@router.get("/actions/{event_id}", response_model=List[Dict[str, Any]])
async def list_event_actions(event_id: str):
    """Fetches containment action history for a specific incident."""
    return get_actions_for_event(event_id)

@router.get("/actions", response_model=List[Dict[str, Any]])
async def list_all_actions(limit: int = 50):
    """Fetches recent containment action audit logs across all incidents."""
    return get_all_remediation_actions(limit=limit)

@router.post("/status", response_model=Dict[str, Any])
async def update_status(request: StatusUpdateRequest):
    """Updates the status of an incident (Detected, Investigating, Mitigated, Resolved)."""
    success = update_incident_status(request.event_id, request.status)
    if not success:
        raise HTTPException(status_code=404, detail="Incident not found or status update failed")
    return {"message": f"Incident {request.event_id} status updated to {request.status}", "status": request.status}
