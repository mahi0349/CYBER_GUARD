import winreg
import platform
from typing import List, Dict, Any

class SoftwareCollector:
    def __init__(self):
        pass

    def collect(self) -> List[Dict[str, Any]]:
        if platform.system() != "Windows":
            return []

        apps = []
        seen = set()

        registry_targets = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "64-bit"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "32-bit"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", "User")
        ]

        for hive, subkey, arch in registry_targets:
            try:
                key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
                count = winreg.QueryInfoKey(key)[0]
                for i in range(count):
                    try:
                        child_name = winreg.EnumKey(key, i)
                        child_key = winreg.OpenKey(key, child_name, 0, winreg.KEY_READ)

                        display_name = self._get_val(child_key, "DisplayName")
                        if not display_name:
                            continue

                        # Avoid exact duplicates from multiple hives
                        display_version = self._get_val(child_key, "DisplayVersion") or "Unknown"
                        dedup_key = f"{display_name.strip()}::{display_version.strip()}".lower()
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        publisher = self._get_val(child_key, "Publisher") or "Unknown"
                        install_date = self._get_val(child_key, "InstallDate") or "Unknown"
                        install_location = self._get_val(child_key, "InstallLocation") or ""
                        uninstall_string = self._get_val(child_key, "UninstallString") or ""

                        # Security status heuristic
                        security_status = "VERIFIED"
                        if not publisher or publisher.lower() in ["unknown", "n/a", ""]:
                            security_status = "UNKNOWN_PUBLISHER"

                        apps.append({
                            "name": display_name.strip(),
                            "version": display_version.strip(),
                            "publisher": publisher.strip(),
                            "install_date": install_date,
                            "install_location": install_location,
                            "architecture": arch,
                            "security_status": security_status
                        })
                    except Exception:
                        continue
            except Exception:
                continue

        apps.sort(key=lambda x: x["name"].lower())
        return apps

    def _get_val(self, key, val_name: str):
        try:
            val, _ = winreg.QueryValueEx(key, val_name)
            return str(val) if val is not None else None
        except Exception:
            return None

software_collector = SoftwareCollector()
