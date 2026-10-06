from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class AgentStatusOut(BaseModel):
    device_id: str
    hostname: str
    os_name: str
    os_version: str
    agent_version: str
    status: str # ONLINE, DEGRADED, OFFLINE
    last_telemetry_at: Optional[str] = None
    telemetry_age_seconds: Optional[int] = None
    registered_at: Optional[str] = None

class SystemTelemetryOut(BaseModel):
    timestamp: str
    hostname: str
    os_name: str
    os_version: str
    os_release: Optional[str] = None
    architecture: Optional[str] = None
    cpu_percent: float
    cpu_cores: int
    memory_percent: float
    memory_used_mb: float
    memory_total_mb: float
    memory_available_mb: float
    disk_percent: float
    disk_used_gb: float
    disk_total_gb: float
    disk_free_gb: float
    net_bytes_sent_sec: float
    net_bytes_recv_sec: float
    total_bytes_sent: int
    total_bytes_recv: int
    uptime_seconds: int
    boot_time: Optional[str] = None

class ProcessItemOut(BaseModel):
    pid: int
    ppid: Optional[int] = None
    name: str
    exe_path: Optional[str] = None
    cmdline: Optional[str] = None
    username: Optional[str] = None
    status: str
    cpu_percent: float
    memory_mb: float
    memory_percent: float
    create_time: Optional[str] = None
    risk_score: int = 0
    risk_level: str = "SAFE"
    risk_reasons: List[str] = []

class NetworkItemOut(BaseModel):
    pid: int
    process_name: str
    protocol: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: Any # int or str "-"
    state: str
    risk_score: int = 0
    risk_level: str = "SAFE"
    risk_reasons: List[str] = []

class DefenderStatusOut(BaseModel):
    available: bool
    status: str
    reason: Optional[str] = None
    am_running_mode: Optional[str] = None
    real_time_protection: bool = False
    antivirus_enabled: bool = False
    antispyware_enabled: bool = False
    behavior_monitor_enabled: bool = False
    signature_version: str = "Unknown"
    signature_age_days: int = 0
    quick_scan_age_days: int = 0
    engine_version: Optional[str] = None
    recent_threats: List[Dict[str, Any]] = []
    last_checked: Optional[str] = None

class FirewallProfileOut(BaseModel):
    enabled: bool
    default_inbound: Optional[str] = None
    default_outbound: Optional[str] = None

class FirewallStatusOut(BaseModel):
    available: bool
    status: str
    reason: Optional[str] = None
    profiles: Dict[str, FirewallProfileOut] = {}
    all_enabled: bool = False
    last_checked: Optional[str] = None

class ProtectionStatusOut(BaseModel):
    defender: DefenderStatusOut
    firewall: FirewallStatusOut

class SoftwareItemOut(BaseModel):
    name: str
    version: str
    publisher: str
    install_date: Optional[str] = None
    install_location: Optional[str] = None
    architecture: str
    security_status: str

class ServiceItemOut(BaseModel):
    name: str
    display_name: str
    status: str
    start_type: str
    bin_path: Optional[str] = None
    username: Optional[str] = None
    suspicious: bool = False
    risk_reason: Optional[str] = None

class StartupItemOut(BaseModel):
    name: str
    path: str
    source: str
    enabled: bool
    suspicious: bool = False
    reasons: List[str] = []

class TrackedFileOut(BaseModel):
    name: str
    path: str
    size: int
    is_executable: bool
    extension: str
    sha256: Optional[str] = None
    last_modified: Optional[str] = None

class SecurityEventOut(BaseModel):
    timestamp: str
    severity: str
    event_type: str
    source: str
    description: str
    user: Optional[str] = None
    process: Optional[str] = None
    metadata: Dict[str, Any] = {}

class ThreatAlertOut(BaseModel):
    id: str
    severity: str
    category: str
    title: str
    detection_source: str
    evidence: List[Dict[str, Any]]
    explanation: str
    affected_object: Optional[str] = None
    recommended_action: str
    created_at: str

class RiskContributor(BaseModel):
    factor: str
    impact: int
    type: str # 'penalty' (increases risk) or 'credit' (reduces risk)

class RiskScoreOut(BaseModel):
    score: int # 0 - 100
    level: str # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    breakdown: Dict[str, int]
    contributors: List[RiskContributor]
    summary: str

class ScanTriggerRequest(BaseModel):
    scan_type: str = "quick" # quick, process, startup, network, file, config
    device_id: Optional[str] = None

class ScanRecordOut(BaseModel):
    scan_id: str
    scan_type: str
    status: str # QUEUED, RUNNING, COMPLETED, FAILED, UNAVAILABLE
    findings_count: int
    started_at: str
    completed_at: Optional[str] = None
    summary: Optional[Dict[str, Any]] = None
