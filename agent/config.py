import os
import socket
import platform
from pydantic import BaseModel
from typing import List

class AgentConfig(BaseModel):
    agent_name: str = "QuantumVault-Endpoint-Agent"
    version: str = "1.0.0"
    device_id: str = socket.gethostname().lower()
    hostname: str = socket.gethostname()
    os_name: str = platform.system()
    os_version: str = platform.version()
    
    # Backend URLs
    backend_http_url: str = "http://127.0.0.1:8000/api/v1/command-center"
    backend_ws_url: str = "ws://127.0.0.1:8000/api/v1/command-center/agent-ws"
    api_token: str = "qv-endpoint-agent-token-2026"
    
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
