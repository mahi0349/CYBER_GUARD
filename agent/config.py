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

import sys
import json
from pathlib import Path

# Resolve backend URL: CLI flag > ENV var > agent_config.json > localhost default
_cli_backend = None
for _idx, _arg in enumerate(sys.argv):
    if _arg in ("--backend", "-b") and _idx + 1 < len(sys.argv):
        _cli_backend = sys.argv[_idx + 1]
        break
    elif _arg.startswith("http://") or _arg.startswith("https://"):
        _cli_backend = _arg
        break

_file_backend = None
try:
    _exe_dir = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path.cwd()
    for _cfg_file in (Path.cwd() / "agent_config.json", _exe_dir / "agent_config.json"):
        if _cfg_file.exists():
            with open(_cfg_file, "r", encoding="utf-8") as _f:
                _data = json.load(_f)
                _file_backend = _data.get("backend_url")
                if _file_backend:
                    break
except Exception:
    pass

_base_url = (
    _cli_backend
    or os.environ.get("QUANTUMVAULT_BACKEND_URL")
    or _file_backend
    or "http://127.0.0.1:8000"
).rstrip("/")

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

    # Magic Link Dashboard Auto-open
    dashboard_url: str = os.environ.get("QUANTUMVAULT_DASHBOARD_URL", "http://localhost:5173").rstrip("/")
    auto_open_browser: bool = os.environ.get("QUANTUMVAULT_AUTO_OPEN", "true").lower() in ("true", "1", "yes")
    
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
