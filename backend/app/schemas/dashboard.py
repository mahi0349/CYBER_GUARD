from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Any, Dict
from datetime import datetime

class ThreatEvidenceOut(BaseModel):
    id: int
    indicator: str
    description: str
    weight: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ThreatOut(BaseModel):
    id: int
    threat_type: str
    source_type: str
    source_payload: Optional[str] = None
    severity: str
    risk_score: int
    confidence: float
    status: str
    explanation: Optional[str] = None
    created_at: datetime
    evidence: List[ThreatEvidenceOut] = []

    model_config = ConfigDict(from_attributes=True)

class IncidentOut(BaseModel):
    id: int
    threat_id: Optional[int] = None
    incident_code: str
    title: str
    description: str
    severity: str
    status: str
    assigned_to: str
    mitre_technique: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class ActionExecutionRequest(BaseModel):
    action_type: str  # block_url, revoke_session, require_mfa, block_ip, quarantine_message
    notes: Optional[str] = None

class DashboardStats(BaseModel):
    total_events_analyzed: int
    threats_detected: int
    critical_threats: int
    active_incidents: int
    phishing_count: int
    deepfake_count: int
    account_takeover_count: int
    severity_distribution: Dict[str, int]
    timeline: List[Dict[str, Any]]
    recent_threats: List[ThreatOut]
    recent_incidents: List[IncidentOut]
