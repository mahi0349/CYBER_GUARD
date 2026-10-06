from typing import List, Dict, Any
from datetime import datetime, timezone

class DetectionEngine:
    def __init__(self):
        pass

    def evaluate_threats(
        self,
        defender_data: Dict[str, Any],
        firewall_data: Dict[str, Any],
        startup_items: List[Dict[str, Any]],
        processes: List[Dict[str, Any]],
        network_conns: List[Dict[str, Any]],
        file_events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        alerts = []

        # 1. Defender Protection Disabled
        if defender_data.get("available"):
            if not defender_data.get("real_time_protection"):
                alerts.append({
                    "id": f"def-rtp-{int(datetime.now(timezone.utc).timestamp())}",
                    "severity": "HIGH",
                    "category": "Endpoint Protection",
                    "title": "Microsoft Defender Real-Time Protection is Disabled",
                    "detection_source": "Windows Security Center",
                    "evidence": [{"indicator": "RealTimeProtectionEnabled", "value": "False"}],
                    "explanation": "Microsoft Defender real-time scanning engine is turned off, leaving the host vulnerable to unmonitored script execution and binary payloads.",
                    "affected_object": "Microsoft Defender Antivirus",
                    "recommended_action": "Enable Real-Time Protection in Windows Security Settings.",
                    "created_at": datetime.now(timezone.utc).isoformat()
                })

            if defender_data.get("signature_age_days", 0) > 7:
                alerts.append({
                    "id": f"def-sig-{int(datetime.now(timezone.utc).timestamp())}",
                    "severity": "MEDIUM",
                    "category": "Signature Staleness",
                    "title": "Antivirus Signatures Outdated (> 7 days)",
                    "detection_source": "Windows Defender",
                    "evidence": [{"indicator": "AntivirusSignatureAge", "value": f"{defender_data.get('signature_age_days')} days"}],
                    "explanation": "Security intelligence definitions have not updated in over a week.",
                    "affected_object": "Security Intelligence Update",
                    "recommended_action": "Run Windows Defender signature update.",
                    "created_at": datetime.now(timezone.utc).isoformat()
                })

        # 2. Firewall Disabled
        if firewall_data.get("available") and not firewall_data.get("all_enabled"):
            disabled_profiles = [
                name for name, p in firewall_data.get("profiles", {}).items() if not p.get("enabled")
            ]
            if disabled_profiles:
                alerts.append({
                    "id": f"fw-dis-{int(datetime.now(timezone.utc).timestamp())}",
                    "severity": "HIGH",
                    "category": "Network Defense",
                    "title": f"Windows Firewall Disabled for Profiles: {', '.join(disabled_profiles)}",
                    "detection_source": "Windows Advanced Firewall",
                    "evidence": [{"indicator": "DisabledProfiles", "value": ", ".join(disabled_profiles)}],
                    "explanation": "One or more network firewall profiles are inactive, allowing unsolicited inbound connections.",
                    "affected_object": "Windows Firewall",
                    "recommended_action": "Re-enable all profiles via Windows Security or PowerShell 'Set-NetFirewallProfile -Enabled True'.",
                    "created_at": datetime.now(timezone.utc).isoformat()
                })

        # 3. Suspicious Startup Entries
        for s in startup_items:
            if s.get("suspicious"):
                alerts.append({
                    "id": f"start-{s.get('name')}",
                    "severity": "HIGH",
                    "category": "Persistence",
                    "title": f"Suspicious Startup Entry: {s.get('name')}",
                    "detection_source": s.get("source", "Registry Run"),
                    "evidence": [{"indicator": r, "value": s.get("path")} for r in s.get("reasons", [])],
                    "explanation": f"Executable or script registered in startup location exhibiting unusual characteristics: {', '.join(s.get('reasons', []))}.",
                    "affected_object": s.get("path"),
                    "recommended_action": "Inspect the file path and remove the entry if unauthorized.",
                    "created_at": datetime.now(timezone.utc).isoformat()
                })

        # 4. Suspicious Processes
        for p in processes:
            if p.get("risk_level") in ["HIGH", "CRITICAL"]:
                alerts.append({
                    "id": f"proc-{p.get('pid')}",
                    "severity": p.get("risk_level"),
                    "category": "Execution Anomaly",
                    "title": f"Potentially Suspicious Process: {p.get('name')} (PID {p.get('pid')})",
                    "detection_source": "Process Heuristics",
                    "evidence": [{"indicator": r, "value": p.get("exe_path")} for r in p.get("risk_reasons", [])],
                    "explanation": f"Process execution from non-standard path: {', '.join(p.get('risk_reasons', []))}.",
                    "affected_object": f"{p.get('name')} (PID {p.get('pid')})",
                    "recommended_action": "Investigate process origin and terminate if not recognized.",
                    "created_at": datetime.now(timezone.utc).isoformat()
                })

        # 5. Network Anomalies
        for n in network_conns:
            if n.get("risk_level") == "HIGH":
                alerts.append({
                    "id": f"net-{n.get('pid')}-{n.get('local_port')}",
                    "severity": "HIGH",
                    "category": "Network Anomaly",
                    "title": f"Unusual Network Activity: {n.get('process_name')} ({n.get('protocol')})",
                    "detection_source": "Socket Monitor",
                    "evidence": [{"indicator": r, "value": f"{n.get('local_ip')}:{n.get('local_port')} -> {n.get('remote_ip')}:{n.get('remote_port')}"} for r in n.get("risk_reasons", [])],
                    "explanation": f"Connection matches suspicious port heuristic: {', '.join(n.get('risk_reasons', []))}.",
                    "affected_object": f"{n.get('process_name')} (PID {n.get('pid')})",
                    "recommended_action": "Verify if this service should be listening or contacting this port.",
                    "created_at": datetime.now(timezone.utc).isoformat()
                })

        return alerts

detection_engine = DetectionEngine()
