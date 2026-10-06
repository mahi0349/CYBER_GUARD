from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.models.database import get_db

router = APIRouter(prefix="/auth", tags=["Authentication"])

class LoginRequest(BaseModel):
    email: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict

@router.post("/login", response_model=LoginResponse)
def login(creds: LoginRequest, db: Session = Depends(get_db)):
    # Simple analyst authentication for demo/prototype
    if creds.email and creds.password:
        return {
            "access_token": "quantumvault_demo_bearer_token_xyz123",
            "token_type": "bearer",
            "user": {
                "id": 1,
                "name": "SOC Lead Analyst",
                "email": creds.email,
                "role": "tier3_analyst"
            }
        }
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid email or password"
    )

@router.get("/me")
def get_me():
    return {
        "id": 1,
        "name": "SOC Lead Analyst",
        "email": "analyst@quantumvault.internal",
        "role": "tier3_analyst"
    }
