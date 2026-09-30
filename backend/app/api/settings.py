from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import logging

from app.config import settings
from app.models.database import get_db, get_database_status, try_connect_postgres
from app.models.settings import SystemPolicy
from app.schemas.settings import PolicyUpdateRequest, PolicyResponse, DatabaseStatusResponse

logger = logging.getLogger("cyberguard.api.settings")
router = APIRouter(prefix="/settings", tags=["Risk Policy & Platform Settings"])

def get_or_create_policy(db: Session) -> SystemPolicy:
    try:
        policy = db.query(SystemPolicy).first()
    except Exception:
        db.rollback()
        from app.models.database import Base, engine
        Base.metadata.create_all(bind=engine)
        policy = db.query(SystemPolicy).first()

    if not policy:
        policy = SystemPolicy(
            low_threshold=settings.RISK_THRESHOLD_LOW,
            medium_threshold=settings.RISK_THRESHOLD_MEDIUM,
            high_threshold=settings.RISK_THRESHOLD_HIGH,
            critical_threshold=settings.RISK_THRESHOLD_CRITICAL,
            gemini_model=settings.GEMINI_MODEL
        )
        db.add(policy)
        db.commit()
        db.refresh(policy)
    return policy

@router.get("/policy", response_model=PolicyResponse)
def get_risk_policy(db: Session = Depends(get_db)):
    """Fetch current SOC risk threshold policy and live database status."""
    policy = get_or_create_policy(db)
    db_status = get_database_status(db)
    
    return PolicyResponse(
        low_threshold=policy.low_threshold,
        medium_threshold=policy.medium_threshold,
        high_threshold=policy.high_threshold,
        critical_threshold=policy.critical_threshold,
        gemini_model=policy.gemini_model,
        updated_at=policy.updated_at.isoformat() if policy.updated_at else None,
        database=DatabaseStatusResponse(**db_status)
    )

@router.put("/policy", response_model=PolicyResponse)
def update_risk_policy(payload: PolicyUpdateRequest, db: Session = Depends(get_db)):
    """
    Update deterministic risk scoring cutoffs.
    Enforces strict ascending monotonicity: 0 <= Low < Medium < High < Critical <= 100.
    Immediately synchronizes thresholds in runtime memory and persistent storage.
    """
    if not (0 <= payload.low_threshold < payload.medium_threshold < payload.high_threshold < payload.critical_threshold <= 100):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Thresholds must satisfy strict order: 0 <= Low < Medium < High < Critical <= 100"
        )
    
    policy = get_or_create_policy(db)
    policy.low_threshold = payload.low_threshold
    policy.medium_threshold = payload.medium_threshold
    policy.high_threshold = payload.high_threshold
    policy.critical_threshold = payload.critical_threshold
    
    if payload.gemini_model:
        policy.gemini_model = payload.gemini_model
        settings.GEMINI_MODEL = payload.gemini_model

    # Synchronize runtime settings for immediate effect across all detection engines
    settings.RISK_THRESHOLD_LOW = payload.low_threshold
    settings.RISK_THRESHOLD_MEDIUM = payload.medium_threshold
    settings.RISK_THRESHOLD_HIGH = payload.high_threshold
    settings.RISK_THRESHOLD_CRITICAL = payload.critical_threshold

    db.commit()
    db.refresh(policy)
    logger.info(
        f"Updated Risk Engine cutoffs: Low={policy.low_threshold}, Med={policy.medium_threshold}, "
        f"High={policy.high_threshold}, Crit={policy.critical_threshold}"
    )

    db_status = get_database_status(db)
    return PolicyResponse(
        low_threshold=policy.low_threshold,
        medium_threshold=policy.medium_threshold,
        high_threshold=policy.high_threshold,
        critical_threshold=policy.critical_threshold,
        gemini_model=policy.gemini_model,
        updated_at=policy.updated_at.isoformat() if policy.updated_at else None,
        database=DatabaseStatusResponse(**db_status)
    )

@router.get("/db-status", response_model=DatabaseStatusResponse)
def get_db_diagnostics(db: Session = Depends(get_db)):
    """Return live database driver info, Docker PostgreSQL availability, and telemetry counts."""
    return get_database_status(db)

@router.post("/db-reconnect")
def reconnect_postgres():
    """Attempt dynamic connection to Docker PostgreSQL container."""
    success, message = try_connect_postgres()
    if not success:
        return {
            "success": False,
            "message": message,
            "status": get_database_status()
        }
    return {
        "success": True,
        "message": message,
        "status": get_database_status()
    }
