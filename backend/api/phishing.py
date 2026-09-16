from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException
from ..data.phishing_corpus import TRAINING_AND_TEST_SAMPLES
from ..models.schemas import PhishingAnalysisRequest, ThreatDetectionResult
from ..modules.phishing.detector import PhishingDetector

router = APIRouter(prefix="/analyze/phishing", tags=["Phishing Detection (Scenario A)"])
detector = PhishingDetector()

@router.post("", response_model=ThreatDetectionResult)
async def analyze_phishing_message(request: PhishingAnalysisRequest):
    """Analyzes text, headers, and URLs for phishing, credential harvesting, and social engineering attacks."""
    if not (request.text or request.subject or request.urls):
        raise HTTPException(status_code=400, detail="At least one of 'text', 'subject', or 'urls' must be provided.")
    return detector.analyze(request)

@router.get("/samples", response_model=List[Dict[str, Any]])
async def get_phishing_samples():
    """Returns curated benchmark and test samples for instant one-click analysis."""
    return TRAINING_AND_TEST_SAMPLES

@router.get("/evaluate", response_model=Dict[str, Any])
async def evaluate_phishing_model():
    """Evaluates the machine learning classifier against the labeled test corpus."""
    return detector.ml_classifier.evaluate()
