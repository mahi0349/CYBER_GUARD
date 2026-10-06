import subprocess
import json
import platform
from datetime import datetime, timezone
from typing import Dict, Any

class FirewallCollector:
    def __init__(self):
        pass

    def collect(self) -> Dict[str, Any]:
        if platform.system() != "Windows":
            return {
                "available": False,
                "status": "UNAVAILABLE",
                "reason": "Non-Windows Operating System",
                "profiles": {
                    "Domain": {"enabled": False},
                    "Private": {"enabled": False},
                    "Public": {"enabled": False}
                },
                "all_enabled": False
            }

        ps_cmd = (
            "Get-NetFirewallProfile | Select-Object -Property "
            "Name, Enabled, DefaultInboundAction, DefaultOutboundAction | ConvertTo-Json -Compress"
        )

        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=6
            )

            if res.returncode != 0 or not res.stdout.strip():
                # Fallback to netsh advfirewall show allprofiles
                return self.collect_netsh_fallback()

            data = json.loads(res.stdout.strip())
            if isinstance(data, dict):
                data = [data]

            profiles = {}
            for item in data:
                name = item.get("Name", "Unknown")
                enabled_val = item.get("Enabled")
                # In PowerShell, Enabled can be True/False or 1/0
                is_enabled = bool(enabled_val) if isinstance(enabled_val, bool) else (enabled_val == 1)
                profiles[name] = {
                    "enabled": is_enabled,
                    "default_inbound": str(item.get("DefaultInboundAction", "Block")),
                    "default_outbound": str(item.get("DefaultOutboundAction", "Allow"))
                }

            all_on = all(p.get("enabled", False) for p in profiles.values()) if profiles else False

            return {
                "available": True,
                "status": "ACTIVE" if all_on else "PARTIAL",
                "reason": None,
                "profiles": profiles,
                "all_enabled": all_on,
                "last_checked": datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            return self.collect_netsh_fallback(reason=str(e))

    def collect_netsh_fallback(self, reason: str = None) -> Dict[str, Any]:
        try:
            res = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if res.returncode == 0:
                text = res.stdout
                profiles = {}
                for p_name in ["Domain", "Private", "Public"]:
                    is_on = f"{p_name} Profile Settings:" in text and "State                                 ON" in text
                    profiles[p_name] = {"enabled": is_on, "default_inbound": "Block", "default_outbound": "Allow"}

                all_on = all(p["enabled"] for p in profiles.values())
                return {
                    "available": True,
                    "status": "ACTIVE" if all_on else "PARTIAL",
                    "reason": reason,
                    "profiles": profiles,
                    "all_enabled": all_on,
                    "last_checked": datetime.now(timezone.utc).isoformat()
                }
        except Exception:
            pass

        return {
            "available": False,
            "status": "ERROR",
            "reason": reason or "Firewall status could not be read",
            "profiles": {},
            "all_enabled": False
        }

firewall_collector = FirewallCollector()
