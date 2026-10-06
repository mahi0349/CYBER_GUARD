import subprocess
import json
import platform
from datetime import datetime, timezone
from typing import Dict, Any

class DefenderCollector:
    def __init__(self):
        pass

    def collect(self) -> Dict[str, Any]:
        if platform.system() != "Windows":
            return {
                "available": False,
                "status": "UNAVAILABLE",
                "reason": "Non-Windows Operating System",
                "real_time_protection": False,
                "antivirus_enabled": False,
                "antispyware_enabled": False,
                "behavior_monitor_enabled": False,
                "signature_version": "N/A",
                "signature_age_days": -1,
                "quick_scan_age_days": -1,
                "recent_threats": []
            }

        ps_cmd = (
            "Get-MpComputerStatus | Select-Object -Property "
            "AMRunningMode, AntispywareEnabled, AntivirusEnabled, BehaviorMonitorEnabled, "
            "RealTimeProtectionEnabled, AntivirusSignatureAge, AntivirusSignatureVersion, "
            "QuickScanAge, EngineVersion | ConvertTo-Json -Compress"
        )

        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=8
            )

            if res.returncode != 0 or not res.stdout.strip():
                return {
                    "available": False,
                    "status": "PERMISSION_REQUIRED" if "permission" in res.stderr.lower() else "UNAVAILABLE",
                    "reason": res.stderr.strip() or "Defender status query failed",
                    "real_time_protection": False,
                    "antivirus_enabled": False,
                    "antispyware_enabled": False,
                    "behavior_monitor_enabled": False,
                    "signature_version": "N/A",
                    "signature_age_days": -1,
                    "quick_scan_age_days": -1,
                    "recent_threats": []
                }

            data = json.loads(res.stdout.strip())

            # Get recent threats if accessible
            recent_threats = self.collect_recent_threats()

            return {
                "available": True,
                "status": "PROTECTED" if data.get("RealTimeProtectionEnabled") and data.get("AntivirusEnabled") else "DEGRADED",
                "reason": None,
                "am_running_mode": data.get("AMRunningMode", "Normal"),
                "real_time_protection": bool(data.get("RealTimeProtectionEnabled")),
                "antivirus_enabled": bool(data.get("AntivirusEnabled")),
                "antispyware_enabled": bool(data.get("AntispywareEnabled")),
                "behavior_monitor_enabled": bool(data.get("BehaviorMonitorEnabled")),
                "signature_version": str(data.get("AntivirusSignatureVersion", "Unknown")),
                "signature_age_days": int(data.get("AntivirusSignatureAge", 0)),
                "quick_scan_age_days": int(data.get("QuickScanAge", 0)),
                "engine_version": str(data.get("EngineVersion", "Unknown")),
                "recent_threats": recent_threats,
                "last_checked": datetime.now(timezone.utc).isoformat()
            }
        except subprocess.TimeoutExpired:
            return {
                "available": False,
                "status": "TIMEOUT",
                "reason": "PowerShell Defender query timed out",
                "real_time_protection": False,
                "antivirus_enabled": False,
                "antispyware_enabled": False,
                "behavior_monitor_enabled": False,
                "signature_version": "N/A",
                "signature_age_days": -1,
                "quick_scan_age_days": -1,
                "recent_threats": []
            }
        except Exception as e:
            return {
                "available": False,
                "status": "ERROR",
                "reason": str(e),
                "real_time_protection": False,
                "antivirus_enabled": False,
                "antispyware_enabled": False,
                "behavior_monitor_enabled": False,
                "signature_version": "N/A",
                "signature_age_days": -1,
                "quick_scan_age_days": -1,
                "recent_threats": []
            }

    def collect_recent_threats(self):
        try:
            ps_cmd = (
                "Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object -Property "
                "ThreatID, ThreatName, InitialDetectionTime, Resources, DomainUser | "
                "ConvertTo-Json -Compress"
            )
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            if res.returncode == 0 and res.stdout.strip():
                raw = json.loads(res.stdout.strip())
                if isinstance(raw, list):
                    return raw[:10]
                elif isinstance(raw, dict):
                    return [raw]
            return []
        except Exception:
            return []

defender_collector = DefenderCollector()
