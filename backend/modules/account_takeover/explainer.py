"""
Account Takeover & Anomaly Explanation Generator.

Produces SOC-analyst grade natural language rationales with concrete evidence
citations including geo-velocity metrics, brute-force counters, and device entropy.
"""

from typing import Any, Dict, List
from ...models.enums import RiskLevel
from ...models.schemas import ThreatIndicator


class AccountExplainer:
    """Generates human-readable, auditable incident explanations for account anomalies."""

    def generate_explanation(
        self,
        risk_level: RiskLevel,
        threat_classification: str,
        target_username: str,
        anomaly_results: Dict[str, Any],
        indicators: List[ThreatIndicator]
    ) -> str:
        """Constructs an evidence-backed narrative for security operations."""
        if risk_level == RiskLevel.SAFE:
            return (
                f"VERIFIED SAFE: Authentication sequence for user '{target_username}' exhibits normal "
                f"behavioral patterns. Geolocation remains consistent, trusted device fingerprints are recognized, "
                f"and no rapid failure streaks or impossible velocities were detected. "
                f"Account integrity verified across {anomaly_results.get('total_logs_analyzed', 1)} log event(s)."
            )

        parts: List[str] = []

        # Headline
        parts.append(
            f"[{risk_level.value.upper()} SEVERITY] {threat_classification} identified for account '{target_username}'."
        )

        # Impossible Travel Evidence
        travel_events = anomaly_results.get("impossible_travel_events", [])
        if travel_events:
            first_travel = travel_events[0]
            parts.append(
                f"IMPOSSIBLE TRAVEL: Consecutive authentications detected from "
                f"{first_travel['origin_city']} ({first_travel['origin_country']}, IP: {first_travel['origin_ip']}) "
                f"and {first_travel['dest_city']} ({first_travel['dest_country']}, IP: {first_travel['dest_ip']}). "
                f"Physical separation of {first_travel['distance_km']:,.0f} km was traversed in "
                f"{first_travel['time_delta_minutes']} minutes, representing an impossible velocity of "
                f"{first_travel['velocity_kmh']:,.0f} km/h (commercial airliner ceiling: 850 km/h). "
                f"{'Velocity is physically supersonic, confirming remote credential sharing or session theft.' if first_travel.get('is_supersonic') else 'Physical travel in this timeframe is impossible.'}"
            )

        # Brute Force Evidence
        brute_events = anomaly_results.get("brute_force_events", [])
        if brute_events:
            for bf in brute_events:
                ips_str = ", ".join(bf.get("attacker_ips", []))
                if bf.get("final_status") == "SUCCESSFUL_COMPROMISE":
                    parts.append(
                        f"CREDENTIAL BREACH: Attacker conducted {bf['failed_count']} rapid failed login attempts "
                        f"within {bf['duration_seconds']}s from IP(s) {ips_str}, immediately followed by a "
                        f"successful login, indicating password guessing or credential stuffing success."
                    )
                else:
                    parts.append(
                        f"BRUTE FORCE ATTEMPTS: Detected an active sequence of {bf['failed_count']} failed logins "
                        f"within {bf['duration_seconds']}s originating from {ips_str} targeting account '{target_username}'."
                    )

        # Device & MFA Evidence
        device_anomalies = anomaly_results.get("device_anomalies", [])
        if device_anomalies:
            for dev in device_anomalies[:2]:
                if not dev.get("mfa_used"):
                    parts.append(
                        f"DEVICE NOVELTY & MFA BYPASS: Successful authentication occurred from an unrecognized "
                        f"device ({dev.get('fingerprint')[:16]}...) in {dev.get('city') or 'unverified location'} "
                        f"without mandatory Multi-Factor Authentication challenge."
                    )

        # ML Anomaly Evidence
        ml_score = anomaly_results.get("ml_anomaly_score", 0.0)
        if ml_score > 0.60:
            parts.append(
                f"MACHINE LEARNING CONFIRMATION: Isolation Forest multivariate model confirmed statistical "
                f"outlier status (anomaly probability: {ml_score:.1%}) across behavioral feature vectors."
            )

        # Wrap-up SOC advice
        parts.append(
            f"Recommended SOC posture: Terminate active sessions immediately, enforce credential reset, "
            f"and temporarily restrict access from identified attacker IP ranges."
        )

        return " ".join(parts)
