import io
import csv
from datetime import datetime
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from sqlalchemy.orm import Session
from typing import Optional, List, Dict, Any

from app.models.database import get_db
from app.models.threat import Threat, ThreatEvidence, Scan, ModelPrediction
from app.models.incident import Incident
from app.schemas.analysis import (
    URLAnalysisRequest,
    EmailAnalysisRequest,
    LoginLogAnalysisRequest,
    AnalysisResponse
)
from app.services.phishing_service import phishing_service
from app.services.deepfake_service import deepfake_service
from app.services.behavior_service import behavior_service
from app.services.email_analyzer import email_analyzer
from app.services.audio_forensics import audio_forensics_service

router = APIRouter(prefix="/analyze", tags=["Threat Analysis Engine"])

def _persist_threat_and_incident(
    db: Session,
    analysis: AnalysisResponse,
    source_type: str,
    source_payload: str,
    user_id: Optional[int] = 1
) -> tuple[int, Optional[int]]:
    """Persists threat analysis results, evidence, and creates an incident if high/critical risk."""
    
    # 1. Create Threat record
    threat = Threat(
        threat_type=analysis.threat_type,
        source_type=source_type,
        source_payload=source_payload[:500],
        severity=analysis.severity,
        risk_score=analysis.risk_score,
        confidence=analysis.confidence,
        status="active",
        explanation=analysis.explanation,
        created_at=datetime.utcnow()
    )
    db.add(threat)
    db.flush()

    # 2. Add Evidence items
    for item in analysis.evidence:
        ev = ThreatEvidence(
            threat_id=threat.id,
            indicator=item.indicator,
            description=item.description,
            weight=item.weight,
            created_at=datetime.utcnow()
        )
        db.add(ev)

    # 3. Add Model Prediction record
    pred = ModelPrediction(
        threat_id=threat.id,
        model_name=f"{analysis.threat_type}_classifier",
        model_version="1.0.0",
        prediction=analysis.prediction,
        confidence=analysis.confidence,
        created_at=datetime.utcnow()
    )
    db.add(pred)

    # 4. Create Scan record
    scan = Scan(
        user_id=user_id,
        scan_type=source_type,
        input_reference=source_payload[:200],
        result=analysis.prediction,
        risk_score=analysis.risk_score,
        meta_info=analysis.features or {},
        created_at=datetime.utcnow()
    )
    db.add(scan)

    # 5. If severity is HIGH or CRITICAL, automatically raise a SOC Incident
    incident_id = None
    if analysis.severity in ["CRITICAL", "HIGH"]:
        base_code_num = 1000 + threat.id
        incident_code = f"QV-{base_code_num}"
        counter = 1
        while db.query(Incident).filter(Incident.incident_code == incident_code).first():
            incident_code = f"QV-{base_code_num}_{counter}"
            counter += 1
        incident = Incident(
            threat_id=threat.id,
            incident_code=incident_code,
            title=f"Potential {analysis.threat_type.replace('_', ' ').title()} Exploit ({analysis.severity})",
            description=analysis.explanation or f"High risk {analysis.threat_type} detected with score {analysis.risk_score}/100.",
            severity=analysis.severity,
            status="OPEN",
            assigned_to="SOC Lead Analyst",
            mitre_technique=analysis.mitre_technique or "T1566",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(incident)
        db.flush()
        incident_id = incident.id

    db.commit()
    return threat.id, incident_id

@router.post("/url", response_model=AnalysisResponse)
def analyze_url(req: URLAnalysisRequest, db: Session = Depends(get_db)):
    result = phishing_service.analyze_url(req.url)
    threat_id, inc_id = _persist_threat_and_incident(
        db=db,
        analysis=result,
        source_type="url",
        source_payload=req.url
    )
    result.threat_id = threat_id
    result.incident_id = inc_id
    return result

@router.post("/email", response_model=AnalysisResponse)
def analyze_email(req: EmailAnalysisRequest, db: Session = Depends(get_db)):
    # Use the new real email forensic analyzer with SPF/DMARC/MX + NLP
    result = email_analyzer.analyze_email(
        sender=req.sender,
        subject=req.subject,
        body=req.body
    )
    
    threat_id, inc_id = _persist_threat_and_incident(
        db=db,
        analysis=result,
        source_type="email",
        source_payload=f"Subject: {req.subject} | From: {req.sender}"
    )
    result.threat_id = threat_id
    result.incident_id = inc_id
    return result

@router.post("/image", response_model=AnalysisResponse)
async def analyze_image(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    contents = await file.read()
    result = deepfake_service.analyze_image(filename=file.filename or "uploaded_image.jpg", file_bytes=contents)
    threat_id, inc_id = _persist_threat_and_incident(
        db=db,
        analysis=result,
        source_type="image",
        source_payload=file.filename or "uploaded_image.jpg"
    )
    result.threat_id = threat_id
    result.incident_id = inc_id
    return result

@router.post("/audio", response_model=AnalysisResponse)
async def analyze_audio(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    contents = await file.read()
    # Use the real audio forensics service (librosa-based spectral analysis)
    result = audio_forensics_service.analyze_audio(
        filename=file.filename or "audio_recording.wav",
        file_bytes=contents
    )
    threat_id, inc_id = _persist_threat_and_incident(
        db=db,
        analysis=result,
        source_type="audio",
        source_payload=file.filename or "audio_recording.wav"
    )
    result.threat_id = threat_id
    result.incident_id = inc_id
    return result

@router.post("/login-log", response_model=AnalysisResponse)
async def analyze_login_log(
    file: Optional[UploadFile] = File(None),
    user_id: str = Form("U1003"),
    db: Session = Depends(get_db)
):
    events: List[Dict[str, Any]] = []
    
    if file:
        contents = await file.read()
        text_stream = io.StringIO(contents.decode("utf-8", errors="ignore"))
        reader = csv.DictReader(text_stream)
        for row in reader:
            events.append(row)
    else:
        # Default to simulated credential stuffing dataset
        events = [
            {"user_id": user_id, "timestamp": "2026-09-22T03:15:10", "ip_address": "185.220.101.5", "location": "Tor Exit Node (Frankfurt)", "device": "Unknown Linux Headless", "failed_attempts": 14, "success": 0, "user_agent": "Python-urllib/3.9"},
            {"user_id": user_id, "timestamp": "2026-09-22T03:18:22", "ip_address": "185.220.101.5", "location": "Tor Exit Node (Frankfurt)", "device": "Unknown Linux Headless", "failed_attempts": 15, "success": 0, "user_agent": "Python-urllib/3.9"},
            {"user_id": user_id, "timestamp": "2026-09-22T03:21:45", "ip_address": "185.220.101.5", "location": "Tor Exit Node (Frankfurt)", "device": "Unknown Linux Headless", "failed_attempts": 0, "success": 1, "user_agent": "curl/7.68.0"}
        ]

    result = behavior_service.analyze_events(events=events, user_id=user_id)
    threat_id, inc_id = _persist_threat_and_incident(
        db=db,
        analysis=result,
        source_type="login_log",
        source_payload=f"Login events stream for account {user_id}"
    )
    result.threat_id = threat_id
    result.incident_id = inc_id
    return result
