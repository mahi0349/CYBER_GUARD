"""
Account Takeover & Anomaly Detection API Endpoints.

Provides routes for evaluating authentication logs, retrieving curated attack scenarios,
and dynamically generating synthetic authentication log streams.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from ..data.account_samples import get_curated_account_samples
from ..models.schemas import (
    AccountAnomalyAnalysisRequest,
    AuthLogEntry,
    ThreatDetectionResult,
)
from ..modules.account_takeover.detector import AccountAnomalyDetector
from ..modules.account_takeover.log_generator import SyntheticLogGenerator

router = APIRouter(prefix="/analyze/account", tags=["Scenario C: Account Takeover & Anomaly Detection"])

# Shared detector and generator instances
detector = AccountAnomalyDetector()
log_generator = SyntheticLogGenerator()


class GenerateLogsRequest(BaseModel):
    username: str = Field(default="alex.mercer@cyberguard.internal")
    count: int = Field(default=8, ge=2, le=50)
    anomaly_type: str = Field(
        default="impossible_travel",
        description="'impossible_travel' | 'brute_force' | 'new_device' | 'normal'"
    )


@router.post("", response_model=ThreatDetectionResult, summary="Analyze Authentication Logs for Account Takeover")
async def analyze_account(request: AccountAnomalyAnalysisRequest) -> ThreatDetectionResult:
    """
    Evaluates a sequence of authentication logs for anomalous behaviors:
    - Impossible travel velocity violations (Haversine distance vs elapsed time)
    - Brute force and password spraying bursts
    - Unfamiliar device fingerprints and MFA bypasses
    - Multivariate behavioral deviation via Isolation Forest ML
    """
    try:
        result = detector.analyze_logs(request.logs)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Account anomaly detection pipeline encountered an error: {str(e)}"
        )


@router.get("/samples", summary="Get Curated Account Attack and Legitimate Samples")
async def get_samples() -> List[Dict[str, Any]]:
    """Returns curated scenarios including Impossible Travel, Brute Force, Device Hijack, and Clean Baselines."""
    return get_curated_account_samples()


@router.post("/generate", summary="Dynamically Generate Synthetic Authentication Logs")
async def generate_logs(req: GenerateLogsRequest) -> Dict[str, Any]:
    """Generates synthetic authentication logs on demand with customizable threat injection."""
    try:
        logs = log_generator.generate(
            username=req.username,
            count=req.count,
            anomaly_type=req.anomaly_type
        )
        return {
            "username": req.username,
            "anomaly_type": req.anomaly_type,
            "log_count": len(logs),
            "logs": [l.model_dump() for l in logs]
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate synthetic logs: {str(e)}"
        )
