import os
import winreg
import platform
import glob
from typing import List, Dict, Any

class StartupCollector:
    def __init__(self):
        pass

    def collect(self) -> List[Dict[str, Any]]:
        if platform.system() != "Windows":
            return []

        items = []

        # 1. Registry Run keys
        reg_targets = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM:Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM:Run (32-bit)"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU:Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU:RunOnce"),
        ]

        for hive, subkey, src in reg_targets:
            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                num_vals = winreg.QueryInfoKey(key)[1]
                for i in range(num_vals):
                    try:
                        name, val, _ = winreg.EnumValue(key, i)
                        path_str = str(val).strip()
                        suspicious, reasons = self._evaluate_startup_risk(name, path_str)
                        items.append({
                            "name": name,
                            "path": path_str,
                            "source": src,
                            "enabled": True,
                            "suspicious": suspicious,
                            "reasons": reasons
                        })
                    except Exception:
                        continue
            except Exception:
                continue

        # 2. Startup folders
        folder_targets = [
            (os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"), "User Startup Folder"),
            (os.path.join(os.environ.get("PROGRAMDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"), "Common Startup Folder")
        ]

        for folder, src in folder_targets:
            if os.path.exists(folder):
                try:
                    for f in os.listdir(folder):
                        if f.lower() == "desktop.ini":
                            continue
                        full_path = os.path.join(folder, f)
                        suspicious, reasons = self._evaluate_startup_risk(f, full_path)
                        items.append({
                            "name": f,
                            "path": full_path,
                            "source": src,
                            "enabled": True,
                            "suspicious": suspicious,
                            "reasons": reasons
                        })
                except Exception:
                    continue

        return items

    def _evaluate_startup_risk(self, name: str, path: str):
        lower = path.lower()
        reasons = []
        suspicious = False

        if "appdata\\local\\temp" in lower or "windows\\temp" in lower:
            suspicious = True
            reasons.append("Executes from temporary files directory")

        if "\\downloads\\" in lower:
            suspicious = True
            reasons.append("Executes from user Downloads directory")

        if "powershell" in lower and ("-enc" in lower or "-w hidden" in lower or "-nop" in lower):
            suspicious = True
            reasons.append("Contains encoded or hidden PowerShell execution arguments")

        if "cmd.exe" in lower and ("/c" in lower or "echo" in lower):
            suspicious = True
            reasons.append("Invokes command shell script directly on startup")

        return suspicious, reasons

startup_collector = StartupCollector()
