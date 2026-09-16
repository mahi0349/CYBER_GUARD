"""
Curated Sample Scenarios for Account Takeover & Anomaly Detection.

Provides realistic test datasets representing both attacks and clean baseline behavior.
"""

from typing import Any, Dict, List
from ..modules.account_takeover.log_generator import SyntheticLogGenerator


def get_curated_account_samples() -> List[Dict[str, Any]]:
    """Returns preset scenarios with serializable log entries and contextual metadata."""
    gen = SyntheticLogGenerator(seed=101)

    # 1. Impossible Travel
    travel_logs = gen.generate_impossible_travel(
        username="rajesh.kapoor@globalfin.com",
        origin_city="Mumbai",
        dest_city="London",
        time_delta_minutes=12
    )

    # 2. Brute Force
    bf_logs = gen.generate_brute_force(
        username="admin.sys@cloudops.internal",
        city="Moscow",
        failed_attempts=12,
        final_success=True
    )

    # 3. New Device Hijack
    dev_logs = gen.generate_new_device_hijack(
        username="priya.sharma@okcl.org.in",
        home_city="Bangalore",
        attacker_city="Bucharest"
    )

    # 4. Normal Routine
    normal_logs = gen.generate_normal_baseline(
        username="elena.rostova@enterprise.corp",
        city="San Francisco",
        count=6
    )

    return [
        {
            "id": "scenario_impossible_travel",
            "name": "Impossible Travel (Mumbai → London in 12 min)",
            "threat_type": "Impossible Travel / Supersonic Anomaly",
            "expected_risk": "Critical",
            "description": "Legitimate login in Mumbai followed 12 minutes later by access in London (7,200 km, ~36,000 km/h). Physically impossible for human transit.",
            "target_user": "rajesh.kapoor@globalfin.com",
            "log_count": len(travel_logs),
            "logs": [l.model_dump() for l in travel_logs]
        },
        {
            "id": "scenario_brute_force",
            "name": "High-Frequency Brute Force & Credential Breach",
            "threat_type": "Credential Breach via Brute Force",
            "expected_risk": "Critical",
            "description": "12 rapid failed authentication attempts in under 90s from a headless bot script, followed by successful compromise.",
            "target_user": "admin.sys@cloudops.internal",
            "log_count": len(bf_logs),
            "logs": [l.model_dump() for l in bf_logs]
        },
        {
            "id": "scenario_new_device_hijack",
            "name": "Unrecognized Device & MFA Bypass",
            "threat_type": "Unrecognized Device Takeover",
            "expected_risk": "High",
            "description": "Account accessed from an unfamiliar Linux device fingerprint in Bucharest without MFA challenge.",
            "target_user": "priya.sharma@okcl.org.in",
            "log_count": len(dev_logs),
            "logs": [l.model_dump() for l in dev_logs]
        },
        {
            "id": "scenario_normal_baseline",
            "name": "Legitimate Corporate User Routine",
            "threat_type": "Legitimate User Authentication",
            "expected_risk": "Safe",
            "description": "Consistent business hours logins from trusted MacBook in San Francisco with MFA verified.",
            "target_user": "elena.rostova@enterprise.corp",
            "log_count": len(normal_logs),
            "logs": [l.model_dump() for l in normal_logs]
        }
    ]
