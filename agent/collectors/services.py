import psutil
import platform
from typing import List, Dict, Any

class ServicesCollector:
    def __init__(self):
        pass

    def collect(self, limit: int = 200) -> List[Dict[str, Any]]:
        if platform.system() != "Windows":
            return []

        services = []
        try:
            for s in psutil.win_service_iter():
                try:
                    info = s.as_dict()
                    name = info.get("name") or "unknown"
                    display = info.get("display_name") or name
                    status = info.get("status") or "stopped"
                    start_type = info.get("start_type") or "manual"
                    binpath = info.get("binpath") or ""
                    username = info.get("username") or ""

                    # Basic check for suspicious paths
                    suspicious = False
                    reason = None
                    lower_bin = binpath.lower()
                    if "temp" in lower_bin or "downloads" in lower_bin:
                        suspicious = True
                        reason = "Service binary located in temporary/user folder"

                    services.append({
                        "name": name,
                        "display_name": display,
                        "status": status,
                        "start_type": start_type,
                        "bin_path": binpath,
                        "username": username,
                        "suspicious": suspicious,
                        "risk_reason": reason
                    })
                except Exception:
                    continue
        except Exception:
            pass

        # Sort: suspicious first, then running, then alphabetically
        services.sort(key=lambda x: (1 if x["suspicious"] else 0, 1 if x["status"] == "running" else 0, x["name"].lower()), reverse=True)
        return services[:limit]

services_collector = ServicesCollector()
