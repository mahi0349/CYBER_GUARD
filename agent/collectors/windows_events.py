import subprocess
import json
import platform
import re
from datetime import datetime, timezone
from typing import List, Dict, Any

class WindowsEventsCollector:
    def __init__(self):
        self.last_query_time = None

    def collect(self, max_events: int = 15) -> List[Dict[str, Any]]:
        if platform.system() != "Windows":
            return []

        # We query System and Application logs (and Security if accessible)
        # Using Level=1 (Critical), Level=2 (Error), Level=3 (Warning)
        ps_cmd = (
            f"Get-WinEvent -FilterHashtable @{{LogName='System','Application'; Level=1,2,3}} "
            f"-MaxEvents {max_events} -ErrorAction SilentlyContinue | "
            f"Select-Object -Property TimeCreated, Id, LevelDisplayName, ProviderName, Message | "
            f"ConvertTo-Json -Compress"
        )

        try:
            res = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=7
            )

            if res.returncode != 0 or not res.stdout.strip():
                return []

            raw = json.loads(res.stdout.strip())
            if isinstance(raw, dict):
                raw = [raw]

            normalized = []
            for ev in raw:
                event_id = ev.get("Id", 0)
                level_name = str(ev.get("LevelDisplayName", "Information")).lower()
                provider = str(ev.get("ProviderName", "Windows"))
                msg = str(ev.get("Message", "")).strip()

                # Parse timestamp: Powershell returns /Date(1791291733621)/ or ISO string
                ts_str = ev.get("TimeCreated")
                event_time = datetime.now(timezone.utc).isoformat()
                if ts_str:
                    match = re.search(r"/Date\((\d+)\)/", str(ts_str))
                    if match:
                        ms = int(match.group(1))
                        event_time = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
                    else:
                        event_time = str(ts_str)

                # Determine severity
                severity = "LOW"
                if "critical" in level_name:
                    severity = "CRITICAL"
                elif "error" in level_name:
                    severity = "HIGH"
                elif "warning" in level_name:
                    severity = "MEDIUM"

                # Classify event type
                event_type = "system_event"
                if "defender" in provider.lower():
                    event_type = "defender_event"
                elif "firewall" in provider.lower():
                    event_type = "firewall_event"
                elif "service" in provider.lower() or "service control manager" in provider.lower():
                    event_type = "service_change"
                elif "security" in provider.lower() or event_id in [4624, 4625, 4688]:
                    event_type = "authentication_event"

                # Keep description clean and truncated
                clean_desc = msg.split("\n")[0][:250] if msg else f"Event {event_id} from {provider}"

                normalized.append({
                    "timestamp": event_time,
                    "severity": severity,
                    "event_type": event_type,
                    "source": provider,
                    "description": clean_desc,
                    "user": "SYSTEM",
                    "process": provider,
                    "metadata": {
                        "event_id": event_id,
                        "raw_level": level_name,
                        "provider": provider
                    }
                })

            return normalized
        except Exception:
            return []

windows_events_collector = WindowsEventsCollector()
