from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field

from .enums import ActionType, EventSource, IncidentStatus, RiskLevel, ThreatCategory

class ThreatIndicator(BaseModel):
    name: str
    category: str
    weight: float = 1.0
    value: Any = None
    description: str

class RecommendedAction(BaseModel):
    action_type: ActionType
    title: str
    description: str
    priority: int = 1  # 1 = highest, 5 = lowest
    is_automated: bool = False
    executed: bool = False
    executed_at: Optional[datetime] = None

class ThreatDetectionResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: EventSource
    category: ThreatCategory
    threat_classification: str
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Normalized score 0-100")
    risk_level: RiskLevel
    human_explanation: str
    indicators: List[ThreatIndicator] = Field(default_factory=list)
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)
    mitre_attack_techniques: List[str] = Field(default_factory=list)
    target_identity: Optional[str] = None
    origin_ip: Optional[str] = None
    raw_content_summary: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    incident_status: IncidentStatus = IncidentStatus.DETECTED

# Request schemas for modules
class PhishingAnalysisRequest(BaseModel):
    text: Optional[str] = None
    sender: Optional[str] = None
    subject: Optional[str] = None
    urls: List[str] = Field(default_factory=list)
    source_type: EventSource = EventSource.EMAIL

class ImpersonationAnalysisRequest(BaseModel):
    text_content: Optional[str] = None
    claimed_identity: Optional[str] = None
    claimed_organization: Optional[str] = None
    channel: EventSource = EventSource.EMAIL
    urgency_context: Optional[str] = None

class DeepfakeAnalysisRequest(BaseModel):
    image_base64: Optional[str] = None
    filename: Optional[str] = "uploaded_image"
    metadata: Dict[str, Any] = Field(default_factory=dict)

class AuthLogEntry(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    username: str
    ip_address: str
    city: Optional[str] = None
    country: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    device_fingerprint: str
    user_agent: str
    status: str  # "SUCCESS" | "FAILURE"
    mfa_used: bool = False

class AccountAnomalyAnalysisRequest(BaseModel):
    logs: List[AuthLogEntry]

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    environment: str = "production-ready prototype"
    modules: Dict[str, str] = Field(default_factory=dict)
