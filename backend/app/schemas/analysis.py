from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class EvidenceItem(BaseModel):
    indicator: str
    description: str
    weight: int = 5

class URLAnalysisRequest(BaseModel):
    url: str = Field(..., json_schema_extra={"example": "https://secure-chase-online-verify-account.com/login/auth"})

class EmailAnalysisRequest(BaseModel):
    subject: str = Field(..., json_schema_extra={"example": "URGENT: Your account access has been restricted"})
    sender: str = Field(..., json_schema_extra={"example": "security-notice@paypa1-support-team.com"})
    body: str = Field(..., json_schema_extra={"example": "Dear user, please verify your credentials immediately within 24 hours."})

class LoginLogAnalysisRequest(BaseModel):
    user_id: str = "U1003"
    csv_content: Optional[str] = None
    sample_data: Optional[List[Dict[str, Any]]] = None

class AnalysisResponse(BaseModel):
    threat_type: str                  # phishing, deepfake, account_takeover
    prediction: str                   # malicious, suspicious, clean
    confidence: float                 # 0.0 to 1.0
    risk_score: int                   # 0 to 100
    severity: str                     # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    evidence: List[EvidenceItem]
    recommended_actions: List[str]
    explanation: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_name: Optional[str] = None
    features: Optional[Dict[str, Any]] = None
    threat_id: Optional[int] = None
    incident_id: Optional[int] = None
