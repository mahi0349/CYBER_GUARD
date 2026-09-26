import pytest
from app.services.risk_engine import risk_engine
from app.services.phishing_service import phishing_service
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
