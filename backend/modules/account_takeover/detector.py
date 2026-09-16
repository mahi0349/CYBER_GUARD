"""
Account Takeover & Anomaly Detection Orchestrator.

Main entry point coordinating log analysis, physical geo-velocity validation,
Isolation Forest anomaly detection, MITRE ATT&CK mapping, and response actions.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from ...database import save_threat_event
from ...models.enums import (
    ActionType,
    EventSource,
    IncidentStatus,
    RiskLevel,
    ThreatCategory,
)
from ...models.schemas import (
    AuthLogEntry,
    RecommendedAction,
    ThreatDetectionResult,
    ThreatIndicator,
)
from .anomaly_model import AnomalyModel
from .explainer import AccountExplainer
from .mitre_mapper import MitreAccountMapper


class AccountAnomalyDetector:
    """Orchestrates account takeover and authentication anomaly detection."""

    def __init__(self):
        self.anomaly_model = AnomalyModel()
        self.mitre_mapper = MitreAccountMapper()
        self.explainer = AccountExplainer()

    def _score_to_risk_level(self, risk_score: float) -> RiskLevel:
        """Maps 0-100 risk score to standardized RiskLevel enum."""
        if risk_score < 25.0:
            return RiskLevel.SAFE
        elif risk_score < 50.0:
            return RiskLevel.LOW
        elif risk_score < 70.0:
            return RiskLevel.MEDIUM
        elif risk_score < 85.0:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL

    def _classify_threat(
        self,
        anomaly_results: Dict[str, Any],
        risk_level: RiskLevel
    ) -> str:
        """Determines descriptive threat classification string."""
        if risk_level == RiskLevel.SAFE:
            return "Legitimate User Authentication"

        if anomaly_results.get("impossible_travel_events"):
            has_supersonic = any(e.get("is_supersonic") for e in anomaly_results["impossible_travel_events"])
            return "Impossible Travel / Supersonic Anomaly" if has_supersonic else "Impossible Travel / Geo-Velocity Anomaly"

        brute_events = anomaly_results.get("brute_force_events", [])
        if brute_events:
            if any(b.get("final_status") == "SUCCESSFUL_COMPROMISE" for b in brute_events):
                return "Credential Breach via Brute Force / Stuffing"
            return "Active Password Spray / Brute Force Attack"

        if anomaly_results.get("device_anomalies"):
            return "Unrecognized Device Takeover (MFA Bypassed)"

        if anomaly_results.get("ml_anomaly_score", 0.0) > 0.65:
            return "Statistical Behavioral Anomaly (Isolation Forest Outlier)"

        return "Suspicious Authentication Pattern"

    def _generate_response_actions(
        self,
        risk_level: RiskLevel,
        threat_classification: str,
        target_user: str,
        attacker_ip: Optional[str]
    ) -> List[RecommendedAction]:
        """Generates tiered SOC response actions based on risk level and threat type."""
        actions: List[RecommendedAction] = []

        if risk_level == RiskLevel.SAFE:
            actions.append(RecommendedAction(
                action_type=ActionType.ALLOW,
                title="Allow Normal Session",
                description=f"No anomalous patterns detected for '{target_user}'. Allow traffic without restriction.",
                priority=5,
                is_automated=True
            ))
            return actions

        # For HIGH or CRITICAL threats
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            actions.append(RecommendedAction(
                action_type=ActionType.REVOKE_SESSION,
                title="Revoke Active User Sessions",
                description=f"Immediately terminate all active refresh tokens and OAuth web sessions for user '{target_user}'.",
                priority=1,
                is_automated=True
            ))
            actions.append(RecommendedAction(
                action_type=ActionType.REQUIRE_MFA,
                title="Force Step-Up Authentication",
                description=f"Lock account until FIDO2/Hardware Token or MFA verification and mandatory password rotation.",
                priority=1,
                is_automated=True
            ))
            if attacker_ip:
                actions.append(RecommendedAction(
                    action_type=ActionType.BLOCK_IP,
                    title=f"Block Suspicious IP ({attacker_ip})",
                    description=f"Temporarily ban IP address {attacker_ip} across edge reverse proxies and WAF for 24 hours.",
                    priority=2,
                    is_automated=False
                ))
            actions.append(RecommendedAction(
                action_type=ActionType.NOTIFY_ADMIN,
                title="Trigger High-Priority SOC Alert",
                description=f"Dispatch high-priority incident webhook to SOC Tier-2 channel regarding {threat_classification}.",
                priority=2,
                is_automated=True
            ))
            if risk_level == RiskLevel.CRITICAL:
                actions.append(RecommendedAction(
                    action_type=ActionType.ESCALATE_INCIDENT,
                    title="Escalate to Major Security Incident (Tier 3)",
                    description="Trigger automated forensic playbook: capture memory dump, isolate workstation, check lateral movement.",
                    priority=1,
                    is_automated=False
                ))
        elif risk_level == RiskLevel.MEDIUM:
            actions.append(RecommendedAction(
                action_type=ActionType.REQUIRE_MFA,
                title="Enforce MFA Step-Up Challenge",
                description=f"Prompt user '{target_user}' with push notification challenge on registered authenticator.",
                priority=2,
                is_automated=True
            ))
            actions.append(RecommendedAction(
                action_type=ActionType.WARN_USER,
                title="Notify User of Unrecognized Access",
                description=f"Send security alert email/SMS to '{target_user}' regarding unfamiliar login location.",
                priority=3,
                is_automated=True
            ))
            actions.append(RecommendedAction(
                action_type=ActionType.FLAG_MANUAL_REVIEW,
                title="Flag for Identity Audit",
                description="Add user session telemetry to low-priority SOC queue for review within 4 hours.",
                priority=4,
                is_automated=False
            ))
        else:  # LOW
            actions.append(RecommendedAction(
                action_type=ActionType.WARN_USER,
                title="Log Security Warning",
                description="Log low-confidence behavioral discrepancy to user audit trail.",
                priority=4,
                is_automated=True
            ))

        return actions

    def analyze_logs(self, logs: List[AuthLogEntry]) -> ThreatDetectionResult:
        """
        Runs the full account takeover and anomaly detection pipeline on an authentication log sequence.
        Returns a ThreatDetectionResult and commits the incident to the database.
        """
        if not logs:
            empty_id = str(uuid.uuid4())
            return ThreatDetectionResult(
                id=empty_id,
                timestamp=datetime.now(timezone.utc),
                source=EventSource.AUTH_LOG,
                category=ThreatCategory.BENIGN,
                threat_classification="No Activity",
                risk_score=0.0,
                risk_level=RiskLevel.SAFE,
                human_explanation="No authentication logs were supplied for analysis.",
                indicators=[],
                recommended_actions=[
                    RecommendedAction(
                        action_type=ActionType.ALLOW,
                        title="No Action Needed",
                        description="Empty log stream.",
                        priority=5,
                        is_automated=True
                    )
                ],
                mitre_attack_techniques=[],
                target_identity=None,
                origin_ip=None,
                raw_content_summary="Empty log stream."
            )

        # Sort logs chronologically
        sorted_logs = sorted(logs, key=lambda x: x.timestamp)

        # Target user identity
        target_username = sorted_logs[-1].username
        
        # Primary origin or attacker IP
        origin_ip = sorted_logs[-1].ip_address

        # Run anomaly model
        anomaly_results = self.anomaly_model.analyze_logs(sorted_logs)

        # If brute force or travel detected, focus on attacker IP
        if anomaly_results.get("impossible_travel_events"):
            origin_ip = anomaly_results["impossible_travel_events"][0]["dest_ip"]
        elif anomaly_results.get("brute_force_events"):
            ips = anomaly_results["brute_force_events"][0].get("attacker_ips")
            if ips:
                origin_ip = ips[0]

        # Calculate risk score
        risk_score = round(anomaly_results["composite_score"] * 100.0, 1)
        risk_level = self._score_to_risk_level(risk_score)

        # Classify threat
        threat_classification = self._classify_threat(anomaly_results, risk_level)

        # MITRE ATT&CK techniques
        mitre_techniques = self.mitre_mapper.map_techniques(anomaly_results, risk_level)

        # Recommended response actions
        recommended_actions = self._generate_response_actions(
            risk_level=risk_level,
            threat_classification=threat_classification,
            target_user=target_username,
            attacker_ip=origin_ip
        )

        # Human explanation
        human_explanation = self.explainer.generate_explanation(
            risk_level=risk_level,
            threat_classification=threat_classification,
            target_username=target_username,
            anomaly_results=anomaly_results,
            indicators=anomaly_results["indicators"]
        )

        category = (
            ThreatCategory.ACCOUNT_TAKEOVER
            if risk_level != RiskLevel.SAFE
            else ThreatCategory.BENIGN
        )

        raw_summary = (
            f"Auth stream: {len(sorted_logs)} events for '{target_username}' | "
            f"Last location: {sorted_logs[-1].city or 'Unknown'} ({sorted_logs[-1].country or 'Unknown'}) | "
            f"IP: {origin_ip}"
        )

        result = ThreatDetectionResult(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            source=EventSource.AUTH_LOG,
            category=category,
            threat_classification=threat_classification,
            risk_score=risk_score,
            risk_level=risk_level,
            human_explanation=human_explanation,
            indicators=anomaly_results["indicators"],
            recommended_actions=recommended_actions,
            mitre_attack_techniques=mitre_techniques,
            target_identity=target_username,
            origin_ip=origin_ip,
            raw_content_summary=raw_summary,
            metadata={
                "total_logs": len(sorted_logs),
                "impossible_travel_events": anomaly_results["impossible_travel_events"],
                "brute_force_events": anomaly_results["brute_force_events"],
                "device_anomalies": anomaly_results["device_anomalies"],
                "ml_anomaly_score": anomaly_results["ml_anomaly_score"],
                "rule_anomaly_score": anomaly_results["rule_anomaly_score"],
                "users_involved": anomaly_results["users_involved"],
                "devices_involved": anomaly_results["devices_involved"],
                "ips_involved": anomaly_results["ips_involved"],
            },
            incident_status=IncidentStatus.DETECTED if risk_level != RiskLevel.SAFE else IncidentStatus.RESOLVED
        )

        # Save to database
        try:
            save_threat_event(result)
        except Exception as e:
            print(f"Warning: Failed to save account threat event to SQLite: {e}")

        return result
