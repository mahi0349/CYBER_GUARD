from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from app.models.database import get_db
from app.models.threat import Threat, ThreatEvidence
from app.schemas.dashboard import ThreatOut

router = APIRouter(prefix="/threats", tags=["Threat Intelligence"])

@router.get("", response_model=List[ThreatOut])
def get_threats(
    skip: int = 0,
    limit: int = 50,
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Threat)
    if threat_type:
        query = query.filter(Threat.threat_type == threat_type)
    if severity:
        query = query.filter(Threat.severity == severity)
    
    threats = query.order_by(Threat.created_at.desc()).offset(skip).limit(limit).all()
    return threats

@router.get("/{threat_id}", response_model=ThreatOut)
def get_threat(threat_id: int, db: Session = Depends(get_db)):
    threat = db.query(Threat).filter(Threat.id == threat_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat
