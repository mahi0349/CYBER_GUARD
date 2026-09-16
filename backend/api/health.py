from fastapi import APIRouter
from ..models.schemas import HealthResponse

router = APIRouter(tags=["Health"])

@router.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="ONLINE",
        service="CYBERGUARD Threat Intelligence Core",
        version="1.0.0",
        environment="production-ready prototype",
        modules={
            "scenario_a_phishing": "READY",
            "scenario_b_deepfake_impersonation": "READY",
            "scenario_c_account_takeover": "READY",
            "unified_risk_engine": "ACTIVE",
            "mitre_attack_mapper": "ACTIVE",
            "response_recommender": "ACTIVE"
        }
    )
