from typing import Dict, Any, List

class EndpointRiskEngine:
    """
    Deterministic, fully explainable endpoint security risk engine.
    Calculates overall host risk score (0-100) based on actual security telemetry.
    """
    def __init__(self):
        pass

    def evaluate(
        self,
        defender_data: Dict[str, Any],
        firewall_data: Dict[str, Any],
        processes: List[Dict[str, Any]],
        network_conns: List[Dict[str, Any]],
        startup_items: List[Dict[str, Any]],
        file_events: List[Dict[str, Any]],
        security_events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        process_risk = 0
        network_risk = 0
        persistence_risk = 0
        file_risk = 0
        config_risk = 0

        contributors = []

        # 1. Security Configuration (Defender & Firewall)
        if defender_data.get("available"):
            if defender_data.get("real_time_protection") and defender_data.get("antivirus_enabled"):
                contributors.append({"factor": "Defender active & real-time protection enabled", "impact": -10, "type": "credit"})
            else:
                config_risk += 35
                contributors.append({"factor": "Defender real-time protection disabled", "impact": 35, "type": "penalty"})

            sig_age = defender_data.get("signature_age_days", 0)
            if sig_age > 7:
                config_risk += 15
                contributors.append({"factor": f"Defender signatures outdated ({sig_age} days)", "impact": 15, "type": "penalty"})
        else:
            config_risk += 10
            contributors.append({"factor": "Endpoint Defender status unavailable", "impact": 10, "type": "penalty"})

        if firewall_data.get("available"):
            if firewall_data.get("all_enabled"):
                contributors.append({"factor": "Windows Firewall active on all profiles", "impact": -10, "type": "credit"})
            else:
                config_risk += 25
                contributors.append({"factor": "Windows Firewall disabled on one or more profiles", "impact": 25, "type": "penalty"})
        else:
            config_risk += 10
            contributors.append({"factor": "Endpoint Firewall status unavailable", "impact": 10, "type": "penalty"})

        # 2. Persistence / Startup Risk
        suspicious_startup_count = sum(1 for s in startup_items if s.get("suspicious"))
        if suspicious_startup_count > 0:
            added = min(suspicious_startup_count * 20, 40)
            persistence_risk += added
            contributors.append({"factor": f"{suspicious_startup_count} suspicious startup entry detected", "impact": added, "type": "penalty"})

        # 3. Process Risk
        high_risk_procs = [p for p in processes if p.get("risk_level") in ["HIGH", "CRITICAL"]]
        med_risk_procs = [p for p in processes if p.get("risk_level") == "MEDIUM"]

        if high_risk_procs:
            added = min(len(high_risk_procs) * 20, 40)
            process_risk += added
            contributors.append({"factor": f"{len(high_risk_procs)} process with elevated execution anomaly", "impact": added, "type": "penalty"})
        elif med_risk_procs:
            added = min(len(med_risk_procs) * 10, 20)
            process_risk += added
            contributors.append({"factor": f"{len(med_risk_procs)} process with non-standard attributes", "impact": added, "type": "penalty"})

        # 4. Network Risk
        high_risk_conns = [c for c in network_conns if c.get("risk_level") == "HIGH"]
        med_risk_conns = [c for c in network_conns if c.get("risk_level") == "MEDIUM"]

        if high_risk_conns:
            added = min(len(high_risk_conns) * 15, 30)
            network_risk += added
            contributors.append({"factor": f"{len(high_risk_conns)} unusual network connection/listener", "impact": added, "type": "penalty"})
        elif med_risk_conns:
            added = min(len(med_risk_conns) * 5, 15)
            network_risk += added
            contributors.append({"factor": f"{len(med_risk_conns)} connection on sensitive port", "impact": added, "type": "penalty"})

        # 5. File Risk
        executable_file_creations = [
            f for f in file_events if f.get("event_type") == "file_created" and f.get("severity") in ["MEDIUM", "HIGH"]
        ]
        if executable_file_creations:
            added = min(len(executable_file_creations) * 8, 20)
            file_risk += added
            contributors.append({"factor": f"{len(executable_file_creations)} executable created in monitored folders", "impact": added, "type": "penalty"})

        # 6. Windows Security Events
        crit_events = [e for e in security_events if e.get("severity") == "CRITICAL"]
        high_events = [e for e in security_events if e.get("severity") == "HIGH"]
        if crit_events:
            config_risk += min(len(crit_events) * 15, 30)
            contributors.append({"factor": f"{len(crit_events)} critical Windows system event detected", "impact": 15, "type": "penalty"})
        elif high_events:
            config_risk += min(len(high_events) * 5, 15)
            contributors.append({"factor": f"{len(high_events)} error event in Windows logs", "impact": 5, "type": "penalty"})

        # Normalize breakdown
        breakdown = {
            "Process Risk": min(process_risk, 40),
            "Network Risk": min(network_risk, 30),
            "Persistence Risk": min(persistence_risk, 40),
            "File Risk": min(file_risk, 20),
            "Security Config": min(config_risk, 40)
        }

        # Net calculation
        raw_score = sum(breakdown.values())
        # Apply credits
        for c in contributors:
            if c["type"] == "credit":
                raw_score += c["impact"] # impact is negative

        final_score = max(0, min(raw_score, 100))

        # Level mapping
        if final_score <= 20:
            level = "SAFE"
        elif final_score <= 40:
            level = "LOW"
        elif final_score <= 60:
            level = "MEDIUM"
        elif final_score <= 80:
            level = "HIGH"
        else:
            level = "CRITICAL"

        # Explainable summary
        if final_score <= 20:
            summary = "Endpoint is well protected with active Defender and Firewall. No high-risk anomalies detected."
        elif final_score <= 40:
            summary = "Endpoint exhibits low risk indicators. Security controls are active."
        elif final_score <= 60:
            summary = "Moderate risk: Review anomalous background activity or configuration alerts."
        elif final_score <= 80:
            summary = "High risk: Inactive endpoint protection or suspicious processes detected."
        else:
            summary = "Critical risk: Multiple severe security controls disabled or active threats detected."

        return {
            "score": final_score,
            "level": level,
            "breakdown": breakdown,
            "contributors": contributors,
            "summary": summary
        }

endpoint_risk_engine = EndpointRiskEngine()
