import os
import psutil
from datetime import datetime, timezone
from typing import List, Dict, Any

class ProcessCollector:
    def __init__(self):
        # Primer for cpu percent calculation
        for p in psutil.process_iter(['pid']):
            try:
                p.cpu_percent(interval=None)
            except Exception:
                pass

    def evaluate_process_risk(self, name: str, exe: str, cmdline: List[str], username: str) -> Dict[str, Any]:
        """
        Evaluate objective risk indicators for a process.
        Does NOT fabricate malware labels; flags suspicious anomalies.
        """
        risk_score = 0
        reasons = []

        lower_exe = (exe or "").lower()
        lower_name = (name or "").lower()

        # Check execution from temporary or unusual folders
        temp_indicators = ["appdata\\local\\temp", "windows\\temp", "appdata\\roaming\\temp"]
        downloads_indicators = ["\\downloads\\"]

        if any(ind in lower_exe for ind in temp_indicators):
            risk_score += 35
            reasons.append("Running from temporary directory")

        if any(ind in lower_exe for ind in downloads_indicators):
            risk_score += 25
            reasons.append("Running directly from user Downloads folder")

        # Masquerading or missing path for non-system process
        if not exe and lower_name not in ["system", "registry", "smss.exe", "csrss.exe"]:
            risk_score += 15
            reasons.append("Process executable path hidden or restricted")

        # Double extension detection (e.g., invoice.pdf.exe)
        if lower_name.endswith(".exe"):
            base = lower_name[:-4]
            suspicious_exts = [".pdf", ".docx", ".xlsx", ".txt", ".png", ".jpg", ".zip"]
            if any(base.endswith(ext) for ext in suspicious_exts):
                risk_score += 45
                reasons.append("Double extension masquerading detected")

        # Categorize
        if risk_score >= 40:
            level = "HIGH"
        elif risk_score >= 20:
            level = "MEDIUM"
        elif risk_score > 0:
            level = "LOW"
        else:
            level = "SAFE"

        return {
            "score": min(risk_score, 100),
            "level": level,
            "reasons": reasons
        }

    def collect(self, limit: int = 250) -> List[Dict[str, Any]]:
        results = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'memory_percent', 'username', 'exe', 'ppid', 'status', 'create_time', 'cmdline']):
            try:
                info = p.info
                name = info.get('name') or "unknown"
                exe = info.get('exe') or ""
                cmdline = info.get('cmdline') or []
                username = info.get('username') or "N/A"
                mem_info = info.get('memory_info')
                mem_mb = round(mem_info.rss / (1024 ** 2), 1) if mem_info else 0.0

                created = None
                if info.get('create_time'):
                    try:
                        created = datetime.fromtimestamp(info['create_time'], tz=timezone.utc).isoformat()
                    except Exception:
                        pass

                risk_meta = self.evaluate_process_risk(name, exe, cmdline, username)

                results.append({
                    "pid": info.get('pid'),
                    "ppid": info.get('ppid'),
                    "name": name,
                    "exe_path": exe,
                    "cmdline": " ".join(cmdline) if isinstance(cmdline, list) else str(cmdline),
                    "username": username,
                    "status": info.get('status') or "running",
                    "cpu_percent": round(info.get('cpu_percent') or 0.0, 1),
                    "memory_mb": mem_mb,
                    "memory_percent": round(info.get('memory_percent') or 0.0, 1),
                    "create_time": created,
                    "risk_score": risk_meta["score"],
                    "risk_level": risk_meta["level"],
                    "risk_reasons": risk_meta["reasons"]
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Sort primarily by CPU and Memory
        results.sort(key=lambda x: (x["risk_score"], x["cpu_percent"], x["memory_mb"]), reverse=True)
        return results[:limit]

process_collector = ProcessCollector()
