import io
import wave
import numpy as np
from PIL import Image
import pytest

from app.services.risk_engine import risk_engine
from app.services.phishing_service import phishing_service
from app.services.behavior_service import behavior_service
from app.services.email_analyzer import email_analyzer
from app.services.audio_forensics import audio_forensics_service
from app.services.deepfake_service import deepfake_service
from app.schemas.analysis import EvidenceItem


def test_risk_engine_safe():
    score, sev = risk_engine.calculate_risk(ml_probability=0.05, evidence=[])
    assert score <= 19
    assert sev == "SAFE"


def test_risk_engine_critical():
    evidence = [
        EvidenceItem(indicator="ip_address_host", description="IP Host", weight=18),
        EvidenceItem(indicator="credential_harvesting_keywords", description="Keywords", weight=14),
        EvidenceItem(indicator="domain_hyphen_spoofing", description="Hyphens", weight=12)
    ]
    score, sev = risk_engine.calculate_risk(ml_probability=0.92, evidence=evidence)
    assert score >= 80
    assert sev == "CRITICAL"


def test_phishing_feature_extraction():
    url = "http://192.168.1.1/login-verify-account-security"
    features, evidence = phishing_service.extract_url_features(url)
    assert features["has_ip"] == 1
    assert features["has_https"] == 0
    assert len(evidence) >= 2


def test_phishing_analysis():
    url = "https://secure-chase-online-verify-account.com/auth"
    res = phishing_service.analyze_url(url)
    assert res.threat_type == "phishing"
    assert res.risk_score >= 60
    assert res.mitre_technique == "T1566"


def test_behavior_analysis_csv_formats():
    # Test CSV string inputs where 'success' is "0" or "false" and 'failed_attempts' is string
    events = [
        {"timestamp": "2026-09-22T03:15:10Z", "ip_address": "185.220.101.5", "location": "Tor Frankfurt", "device": "Linux", "failed_attempts": "12", "success": "0", "user_agent": "Python-urllib/3.9"},
        {"timestamp": "2026-09-22T03:18:22Z", "ip_address": "185.220.101.5", "location": "Tor Frankfurt", "device": "Linux", "failed_attempts": "15", "success": "false", "user_agent": "Python-urllib/3.9"},
        {"timestamp": "2026-09-22T03:21:45Z", "ip_address": "185.220.101.5", "location": "Tor Frankfurt", "device": "Linux", "failed_attempts": "", "success": "1", "user_agent": "curl/7.68.0"},
    ]
    res = behavior_service.analyze_events(events=events, user_id="U1003")
    assert res.threat_type == "account_takeover"
    assert res.prediction in ["malicious", "suspicious"]
    assert res.risk_score >= 60
    assert any(e.indicator == "brute_force_spike" for e in res.evidence)
    assert any(e.indicator == "automated_scripting_client" for e in res.evidence)


def test_email_analyzer():
    res = email_analyzer.analyze_email(
        sender="security@paypa1-update.com",
        subject="URGENT: Your account has been suspended",
        body="Dear user, please verify your credentials immediately or your account will be locked within 24 hours."
    )
    assert res.threat_type == "phishing"
    assert res.risk_score >= 50
    assert any(e.indicator in ["homoglyph_substitution", "brand_domain_impersonation", "urgency_coercion_language", "high_urgency_social_engineering"] for e in res.evidence)


def test_audio_forensics_empty_and_valid():
    # Empty audio bytes should not divide by zero or yield NaN
    empty_res = audio_forensics_service.analyze_audio("empty.wav", b"")
    assert empty_res.threat_type == "deepfake_audio"
    assert empty_res.features["byte_entropy"] == 0.0

    # Valid synthetic sine wave audio
    wav_bytes = io.BytesIO()
    with wave.open(wav_bytes, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(16000)
        samples = (np.sin(2 * np.pi * 440 * np.linspace(0, 1, 16000)) * 32767).astype(np.int16)
        wf.writeframes(samples.tobytes())
    wav_bytes.seek(0)
    
    valid_res = audio_forensics_service.analyze_audio("synth_sample.wav", wav_bytes.getvalue())
    assert valid_res.threat_type == "deepfake_audio"
    assert "sample_rate" in valid_res.features or "byte_entropy" in valid_res.features


def test_deepfake_image_analysis():
    # Valid RGB image
    img = Image.new("RGB", (64, 64), color=(100, 150, 200))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    buf.seek(0)

    res = deepfake_service.analyze_image("sample.jpg", buf.getvalue())
    assert res.threat_type == "deepfake"
    assert "fft_spectral_peak_ratio" in res.features
    assert "noise_residual_std" in res.features


def test_policy_api_persistence():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.config import settings

    with TestClient(app) as client:
        # 1. Fetch current policy
        res = client.get("/api/v1/settings/policy")
        assert res.status_code == 200
        data = res.json()
        assert "low_threshold" in data
        assert "database" in data

        # 2. Update policy
        put_res = client.put("/api/v1/settings/policy", json={
            "low_threshold": 18,
            "medium_threshold": 38,
            "high_threshold": 58,
            "critical_threshold": 78
        })
        assert put_res.status_code == 200
        assert put_res.json()["low_threshold"] == 18
        assert settings.RISK_THRESHOLD_LOW == 18

        # 3. Verify order validation (must fail if low >= med)
        bad_res = client.put("/api/v1/settings/policy", json={
            "low_threshold": 50,
            "medium_threshold": 30,
            "high_threshold": 60,
            "critical_threshold": 80
        })
        assert bad_res.status_code == 400

        # Reset back to defaults
        client.put("/api/v1/settings/policy", json={
            "low_threshold": 20,
            "medium_threshold": 40,
            "high_threshold": 60,
            "critical_threshold": 80
        })

