import os
import platform
import socket
from typing import List
from pydantic import BaseModel


def get_windows_edition():
    if platform.system() != "Windows":
        return platform.system(), platform.version()
    
    release = platform.release()  # e.g. '11' or '10'
    build_str = platform.version()  # e.g. '10.0.26300'
    build_num = 0
    try:
        parts = build_str.split('.')
        build_num = int(parts[-1])
    except Exception:
        pass

    edition_name = ""
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        edition, _ = winreg.QueryValueEx(k, "EditionID")
        if edition.lower() == "professional":
            edition_name = "Pro"
        elif edition.lower() == "core":
            edition_name = "Home"
        elif edition.lower() == "enterprise":
            edition_name = "Enterprise"
        elif edition:
            edition_name = edition
    except Exception:
        pass

    # Microsoft preserved NT major kernel as 10.0 for Windows 11.
    # All Windows 11 builds are >= 22000.
    if release == "11" or build_num >= 22000:
        friendly_os = f"Windows 11 {edition_name}".strip()
    else:
        friendly_os = f"Windows 10 {edition_name}".strip()

    return friendly_os, f"Build {build_num}" if build_num else build_str


_os_name, _os_version = get_windows_edition()

# Resolve backend URL from environment or fallback to localhost
_base_url = os.environ.get("QUANTUMVAULT_BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")
if _base_url.startswith("https://"):
    _default_ws = "wss://" + _base_url[8:] + "/api/v1/command-center/agent-ws"
elif _base_url.startswith("http://"):
    _default_ws = "ws://" + _base_url[7:] + "/api/v1/command-center/agent-ws"
else:
    _default_ws = f"ws://{_base_url}/api/v1/command-center/agent-ws"
    _base_url = f"http://{_base_url}"


class AgentConfig(BaseModel):
    agent_name: str = "QuantumVault-Endpoint-Agent"
    version: str = "1.0.0"
    device_id: str = socket.gethostname().lower()
    hostname: str = socket.gethostname()
    os_name: str = _os_name
    os_version: str = _os_version
    
    # Backend URLs (configurable via QUANTUMVAULT_BACKEND_URL or QUANTUMVAULT_WS_URL)
    backend_http_url: str = os.environ.get("QUANTUMVAULT_HTTP_URL", f"{_base_url}/api/v1/command-center")
    backend_ws_url: str = os.environ.get("QUANTUMVAULT_WS_URL", _default_ws)
    api_token: str = os.environ.get("QUANTUMVAULT_API_TOKEN", "qv-endpoint-agent-token-2026")
    
    # Telemetry intervals (in seconds)
    telemetry_interval: int = 3
    process_interval: int = 5
    network_interval: int = 4
    security_status_interval: int = 15
    software_interval: int = 60
    services_interval: int = 30
    startup_interval: int = 30
    events_interval: int = 10
    
    # Monitored directory paths
    monitored_paths: List[str] = [
        os.path.join(os.environ.get("USERPROFILE", "C:\\"), "Downloads"),
        os.path.join(os.environ.get("APPDATA", "C:\\"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        os.path.join(os.environ.get("TEMP", "C:\\Temp"))
    ]


config = AgentConfig()
