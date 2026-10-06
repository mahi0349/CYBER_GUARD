from fastapi import APIRouter, UploadFile, File, Form, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Optional

from app.models.database import get_db
from app.services.email_auth import analyze_email, email_auth_to_analysis_response
from app.api.analyze import _persist_threat_and_incident

router = APIRouter(prefix="/email", tags=["Email Authenticity"])


@router.post("/analyze")
async def analyze_email_authenticity(
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """
    Analyze a raw .eml file or pasted raw email text for authenticity.
    Accepts either:
      - An uploaded .eml file (multipart)
      - A raw_text form field with pasted email source
    """
    raw_eml = ""

    if file:
        contents = await file.read()
        try:
            raw_eml = contents.decode("utf-8", errors="replace")
        except Exception:
            raw_eml = contents.decode("latin-1", errors="replace")
    elif raw_text:
        raw_eml = raw_text
    else:
        raise HTTPException(
            status_code=400,
            detail="Provide either an .eml file upload or raw_text of the email source."
        )

    if not raw_eml.strip():
        raise HTTPException(status_code=400, detail="Empty email content provided.")

    # Run the email authenticity analysis
    result = analyze_email(raw_eml)

    # Convert to AnalysisResponse for risk engine / incident integration
    analysis_response = email_auth_to_analysis_response(result, raw_eml[:300])

    # Persist threat + create incident if HIGH/CRITICAL
    threat_id, incident_id = _persist_threat_and_incident(
        db=db,
        analysis=analysis_response,
        source_type="email_authenticity",
        source_payload=f"Email Auth: {result.get('evidence', {}).get('from', 'unknown')} | Subject: {result.get('evidence', {}).get('subject', '')[:80]}",
    )

    # Merge persistence IDs into the raw result
    result["threat_id"] = threat_id
    result["incident_id"] = incident_id
    result["explanation"] = analysis_response.explanation

    return result
