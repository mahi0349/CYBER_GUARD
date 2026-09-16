import pytest
from datetime import datetime, timezone
from backend.engine.risk_engine import (
    normalize_risk_score,
    score_to_risk_level,
    calculate_entity_risk,
    correlate_threat_events
)
from backend.engine.response_engine import (
    generate_playbook_actions,
    execute_simulated_action,
    PLAYBOOK_CATALOG
)
from backend.models.enums import RiskLevel, ThreatCategory
from backend.database import (
    init_db,
    save_threat_event,
    get_event_by_id,
    save_remediation_action,
    get_actions_for_event,
    get_dashboard_metrics,
    get_category_distribution,
    get_risk_distribution
)
from backend.models.schemas import ThreatDetectionResult, EventSource, IncidentStatus

def test_normalize_risk_score():
    assert normalize_risk_score(0.85, max_val=1.0) == 85.0
    assert normalize_risk_score(45.678) == 45.7
    assert normalize_risk_score(150.0) == 100.0
    assert normalize_risk_score(-10.0) == 0.0

def test_score_to_risk_level():
    assert score_to_risk_level(95.0) == RiskLevel.CRITICAL
    assert score_to_risk_level(75.0) == RiskLevel.HIGH
    assert score_to_risk_level(50.0) == RiskLevel.MEDIUM
    assert score_to_risk_level(25.0) == RiskLevel.LOW
    assert score_to_risk_level(10.0) == RiskLevel.SAFE

def test_generate_playbook_actions():
    phish_actions = generate_playbook_actions(
        category=ThreatCategory.PHISHING.value,
        risk_level=RiskLevel.HIGH,
        threat_classification="Credential Harvesting Phish"
    )
    assert len(phish_actions) >= 2
    action_types = [a.action_type.value for a in phish_actions]
    assert any("Block URL" in a for a in action_types)
    assert any("Quarantine Email" in a for a in action_types)

    ato_actions = generate_playbook_actions(
        category=ThreatCategory.ACCOUNT_TAKEOVER.value,
        risk_level=RiskLevel.CRITICAL,
        threat_classification="Credential Stuffing Burst",
        origin_ip="198.51.100.12"
    )
    ato_types = [a.action_type.value for a in ato_actions]
    assert any("Revoke Active User Sessions" in a for a in ato_types)
    assert any("Step-Up Multi-Factor" in a for a in ato_types)

def test_execute_and_database_remediation():
    init_db()
    test_event = ThreatDetectionResult(
        source=EventSource.EMAIL,
        category=ThreatCategory.PHISHING,
        threat_classification="Test Phishing Lure",
        risk_score=92.0,
        risk_level=RiskLevel.CRITICAL,
        human_explanation="Urgent password reset lure with suspicious link",
        target_identity="ceo@enterprise.com",
        origin_ip="203.0.113.88",
        incident_status=IncidentStatus.DETECTED
    )
    save_threat_event(test_event)

    stored = get_event_by_id(test_event.id)
    assert stored is not None
    assert stored["incident_status"] == "Detected"

    # Execute simulated playbook action
    action_record = execute_simulated_action(
        event=stored,
        action_key="quarantine_email",
        operator="Lead SOC Analyst",
        notes="Automated containment verified."
    )
    assert action_record["status"] == "SUCCESS"
    assert "Search-Mailbox" in action_record["simulated_command"]

    save_remediation_action(action_record)

    # Check that incident status is now Mitigated
    updated = get_event_by_id(test_event.id)
    assert updated["incident_status"] == "Mitigated"

    actions = get_actions_for_event(test_event.id)
    assert len(actions) == 1
    assert actions[0]["action_key"] == "quarantine_email"

def test_correlate_threat_events():
    mock_events = [
        {
            "id": "ev-1",
            "category": "Phishing & Social Engineering",
            "target_identity": "cfo@company.com",
            "origin_ip": "198.51.100.5",
            "risk_score": 85.0,
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        {
            "id": "ev-2",
            "category": "Account Takeover & Anomaly",
            "target_identity": "cfo@company.com",
            "origin_ip": "198.51.100.5",
            "risk_score": 90.0,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    ]
    correlations = correlate_threat_events(mock_events)
    assert len(correlations) >= 1
    corr = correlations[0]
    assert corr["target_identity"] == "cfo@company.com"
    assert "Multi-Stage Identity Compromise" in corr["correlation_type"]
