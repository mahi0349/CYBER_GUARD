from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.models.database import get_db
from app.models.incident import Incident
from app.schemas.dashboard import IncidentOut, ActionExecutionRequest
from app.services.response_engine import response_engine

router = APIRouter(prefix="/incidents", tags=["Incident Response"])

@router.get("", response_model=List[IncidentOut])
def list_incidents(db: Session = Depends(get_db)):
    return db.query(Incident).order_by(Incident.created_at.desc()).all()

@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident

@router.post("/{incident_id}/action")
def trigger_incident_action(
    incident_id: int,
    request: ActionExecutionRequest,
    db: Session = Depends(get_db)
):
    try:
        result = response_engine.execute_action(
            db=db,
            incident_id=incident_id,
            action_type=request.action_type,
            notes=request.notes or ""
        )
        return {"success": True, "result": result}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
