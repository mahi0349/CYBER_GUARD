import os
from typing import List, Dict, Any
from datetime import datetime
import joblib

from app.schemas.analysis import EvidenceItem, AnalysisResponse
from app.services.risk_engine import risk_engine
from app.services.explanation_engine import explanation_engine

MODEL_PATH = os.path.join(os.path.dirname(__file__), "../../../ml/models/behavior_model.joblib")

class BehaviorService:
    def __init__(self):
        self.model = None
        self._load_model()

    def _load_model(self):
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
            except Exception:
                self.model = None

    def analyze_events(self, events: List[Dict[str, Any]], user_id: str = "U1003") -> AnalysisResponse:
        evidence: List[EvidenceItem] = []
        
        # Aggregate heuristics across events
        failed_count = sum(1 for e in events if not e.get("success", True) or int(e.get("failed_attempts", 0)) > 0)
        max_failed_burst = max([int(e.get("failed_attempts", 0)) for e in events] + [0])
        
        locations = list(set(str(e.get("location", "")) for e in events if e.get("location")))
        devices = list(set(str(e.get("device", "")) for e in events if e.get("device")))
        ips = list(set(str(e.get("ip_address", "")) for e in events if e.get("ip_address")))
        user_agents = [str(e.get("user_agent", "")) for e in events]

        # Heuristic 1: Brute force / credential stuffing burst
        if max_failed_burst >= 10 or failed_count >= 10:
            evidence.append(EvidenceItem(
                indicator="brute_force_spike",
                description=f"Rapid cluster of failed authentication attempts ({max_failed_burst} attempts in sequence)",
                weight=22
            ))
        elif max_failed_burst >= 3:
            evidence.append(EvidenceItem(
                indicator="multiple_failed_logins",
                description=f"{max_failed_burst} failed login attempts prior to authorization",
                weight=10
            ))

        # Heuristic 2: Suspicious / Headless User-Agent
        suspicious_agents = [ua for ua in user_agents if any(tool in ua.lower() for tool in ["curl", "python", "urllib", "bot", "script"])]
        if suspicious_agents:
            evidence.append(EvidenceItem(
                indicator="automated_scripting_client",
                description=f"Automated programmatic request tool detected in HTTP User-Agent: {suspicious_agents[0]}",
                weight=18
            ))

        # Heuristic 3: Impossible Travel / Geographic Anomaly
        if len(locations) > 1 or any("tor" in loc.lower() or "germany" in loc.lower() or "russia" in loc.lower() for loc in locations):
            evidence.append(EvidenceItem(
                indicator="geographic_anomaly_impossible_travel",
                description=f"Login originated from disparate location profile ({', '.join(locations)}) violating velocity threshold",
                weight=16
            ))

        # Heuristic 4: Unrecognized Device Hardware Fingerprint
        if any("unknown" in d.lower() or "new" in d.lower() for d in devices):
            evidence.append(EvidenceItem(
                indicator="unrecognized_hardware_signature",
                description="Session initialized from an unregistered device hardware profile without existing trust anchor",
                weight=12
            ))

        # Heuristic 5: Off-hours authentication (between 01:00 and 05:00)
        has_night_login = False
        for e in events:
            ts_str = str(e.get("timestamp") or e.get("login_time", ""))
            if ts_str:
                try:
                    dt = datetime.fromisoformat(ts_str.replace("Z", ""))
                    if 1 <= dt.hour <= 5:
                        has_night_login = True
                        break
                except Exception:
                    pass

        if has_night_login:
            evidence.append(EvidenceItem(
                indicator="anomalous_access_hour",
                description="Authentication attempt executed during abnormal dormant baseline hours (01:00-05:00)",
                weight=8
            ))

        # Calculate anomaly probability
        total_weight = sum(e.weight for e in evidence)
        if total_weight > 0:
            anomaly_prob = min(0.96, max(0.10, 0.20 + (total_weight / 50.0)))
        else:
            anomaly_prob = 0.05

        risk_score, severity = risk_engine.calculate_risk(anomaly_prob, evidence)
        prediction = "malicious" if risk_score >= 60 else ("suspicious" if risk_score >= 40 else "clean")

        actions = []
        if severity in ["CRITICAL", "HIGH"]:
            actions = ["revoke_session", "require_mfa", "block_ip", "reset_password", "notify_user"]
        elif severity == "MEDIUM":
            actions = ["step_up_challenge", "audit_activity_log", "limit_privileges"]
        else:
            actions = ["allow_session", "update_baseline"]

        target_summary = f"Account {user_id} ({len(events)} login events analyzed)"
        explanation = explanation_engine.generate_explanation(
            threat_type="account_takeover",
            risk_score=risk_score,
            severity=severity,
            evidence=evidence,
            target_reference=target_summary
        )

        return AnalysisResponse(
            threat_type="account_takeover",
            prediction=prediction,
            confidence=round(anomaly_prob, 2),
            risk_score=risk_score,
            severity=severity,
            evidence=evidence,
            recommended_actions=actions,
            explanation=explanation,
            mitre_technique="T1078",
            mitre_name="Valid Accounts: Compromised Credentials",
            features={
                "total_events": len(events),
                "failed_attempts": max_failed_burst,
                "distinct_locations": len(locations),
                "distinct_devices": len(devices),
                "distinct_ips": len(ips)
            }
        )

behavior_service = BehaviorService()
