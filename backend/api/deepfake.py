"""
API routes for Deepfake & Impersonation Detection (Scenario B).

Endpoints:
    POST /api/analyze/deepfake         — Image forensics (multipart file upload)
    POST /api/analyze/impersonation    — Text-based impersonation detection (JSON)
    GET  /api/analyze/deepfake/samples — Curated test samples for one-click demo
"""

import base64
from typing import Any, Dict, List

from fastapi import APIRouter, File, HTTPException, UploadFile

from ..data.deepfake_samples import DEEPFAKE_TEST_SAMPLES
from ..models.schemas import DeepfakeAnalysisRequest, ImpersonationAnalysisRequest, ThreatDetectionResult
from ..modules.deepfake.detector import DeepfakeDetector

router = APIRouter(prefix="/analyze", tags=["Deepfake & Impersonation Detection (Scenario B)"])
detector = DeepfakeDetector()

# Maximum file size: 10MB
MAX_FILE_SIZE = 10 * 1024 * 1024
ALLOWED_CONTENT_TYPES = {"image/jpeg", "image/png", "image/jpg", "image/webp"}


@router.post("/deepfake", response_model=ThreatDetectionResult)
async def analyze_deepfake_image(file: UploadFile = File(None), request: DeepfakeAnalysisRequest = None):
    """
    Analyzes an uploaded image for manipulation artifacts using Error Level Analysis (ELA)
    and DCT frequency-domain forensics.

    Accepts either:
    - Multipart file upload (preferred for browser UI)
    - JSON body with base64-encoded image data
    """
    image_bytes = None
    filename = "uploaded_image"

    # Priority 1: Multipart file upload
    if file and file.filename:
        if file.content_type and file.content_type not in ALLOWED_CONTENT_TYPES:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type '{file.content_type}'. Accepted: JPEG, PNG, WebP."
            )
        image_bytes = await file.read()
        filename = file.filename

        if len(image_bytes) > MAX_FILE_SIZE:
            raise HTTPException(status_code=400, detail="File size exceeds 10MB limit.")

    # Priority 2: Base64-encoded image in JSON body
    elif request and request.image_base64:
        try:
            image_bytes = base64.b64decode(request.image_base64)
            filename = request.filename or "base64_image"
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 image data.")

    if not image_bytes:
        raise HTTPException(
            status_code=400,
            detail="No image provided. Upload a file or provide base64-encoded image data."
        )

    try:
        return detector.analyze_image(image_bytes, filename=filename)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image analysis failed: {str(e)}")


@router.post("/deepfake/base64", response_model=ThreatDetectionResult)
async def analyze_deepfake_base64(request: DeepfakeAnalysisRequest):
    """
    Analyzes a base64-encoded image for manipulation artifacts.
    Alternative endpoint for programmatic/API usage.
    """
    if not request.image_base64:
        raise HTTPException(status_code=400, detail="'image_base64' field is required.")

    try:
        image_bytes = base64.b64decode(request.image_base64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 image data.")

    filename = request.filename or "base64_image"

    try:
        return detector.analyze_image(image_bytes, filename=filename)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image analysis failed: {str(e)}")


@router.post("/impersonation", response_model=ThreatDetectionResult)
async def analyze_impersonation(request: ImpersonationAnalysisRequest):
    """
    Analyzes text content for authority-figure impersonation, organizational identity
    spoofing, and coercive social engineering patterns.
    """
    if not (request.text_content or request.claimed_identity or request.claimed_organization):
        raise HTTPException(
            status_code=400,
            detail="At least one of 'text_content', 'claimed_identity', or 'claimed_organization' must be provided."
        )

    channel = request.channel.value if hasattr(request.channel, 'value') else str(request.channel)

    return detector.analyze_impersonation(
        text_content=request.text_content,
        claimed_identity=request.claimed_identity,
        claimed_organization=request.claimed_organization,
        channel=channel,
        urgency_context=request.urgency_context,
    )


@router.get("/deepfake/samples", response_model=Dict[str, Any])
async def get_deepfake_samples():
    """Returns curated test samples for one-click analysis demo."""
    return DEEPFAKE_TEST_SAMPLES
