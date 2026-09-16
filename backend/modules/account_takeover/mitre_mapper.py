"""
MITRE ATT&CK Technique Mapper for Account Takeover & Anomaly Detection.

Maps detected behavioral anomalies, geo-velocity violations, and brute-force
patterns to standardized MITRE ATT&CK matrix technique IDs and descriptions.
"""

from typing import Any, Dict, List
from ...models.enums import RiskLevel


class MitreAccountMapper:
    """Maps account takeover indicators to MITRE ATT&CK framework techniques."""

    TECHNIQUES = {
        "T1110": "T1110 — Brute Force",
        "T1110.001": "T1110.001 — Brute Force: Password Guessing",
        "T1110.003": "T1110.003 — Brute Force: Password Spraying",
        "T1078": "T1078 — Valid Accounts",
        "T1078.004": "T1078.004 — Valid Accounts: Cloud Accounts",
        "T1586.002": "T1586.002 — Compromise Accounts: Email Accounts",
        "T1539": "T1539 — Steal Web Session Cookie",
        "T1071": "T1071 — Application Layer Protocol",
    }

    def map_techniques(
        self,
        anomaly_results: Dict[str, Any],
        risk_level: RiskLevel
    ) -> List[str]:
        """Returns relevant MITRE ATT&CK techniques based on detected indicators."""
        if risk_level == RiskLevel.SAFE:
            return []

        techniques = set()

        # Brute force patterns
        if anomaly_results.get("brute_force_events"):
            techniques.add(self.TECHNIQUES["T1110"])
            for bf in anomaly_results["brute_force_events"]:
                if bf.get("failed_count", 0) >= 5:
                    techniques.add(self.TECHNIQUES["T1110.001"])
                if len(bf.get("attacker_ips", [])) > 1:
                    techniques.add(self.TECHNIQUES["T1110.003"])

        # Impossible travel implies stolen credentials or session hijack
        if anomaly_results.get("impossible_travel_events"):
            techniques.add(self.TECHNIQUES["T1078"])
            techniques.add(self.TECHNIQUES["T1078.004"])
            techniques.add(self.TECHNIQUES["T1586.002"])

        # Device anomaly without MFA
        if anomaly_results.get("device_anomalies"):
            techniques.add(self.TECHNIQUES["T1078"])
            techniques.add(self.TECHNIQUES["T1539"])

        # Default high/critical baseline if no specific rule caught it but ML did
        if not techniques and risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            techniques.add(self.TECHNIQUES["T1078"])
            techniques.add(self.TECHNIQUES["T1071"])

        return sorted(list(techniques))
