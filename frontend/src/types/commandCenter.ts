export type AgentConnectionStatus = 'ONLINE' | 'DEGRADED' | 'OFFLINE';

export interface AgentStatus {
  device_id: string;
  hostname: string;
  os_name: string;
  os_version: string;
  agent_version: string;
  status: AgentConnectionStatus;
  last_telemetry_at?: string | null;
  telemetry_age_seconds?: number | null;
  registered_at?: string | null;
}

export interface SystemTelemetry {
  timestamp: string;
  hostname: string;
  os_name: string;
  os_version: string;
  os_release?: string;
  architecture?: string;
  cpu_percent: number;
  cpu_cores: number;
  memory_percent: number;
  memory_used_mb: number;
  memory_total_mb: number;
  memory_available_mb: number;
  disk_percent: number;
  disk_used_gb: number;
  disk_total_gb: number;
  disk_free_gb: number;
  net_bytes_sent_sec: number;
  net_bytes_recv_sec: number;
  total_bytes_sent: number;
  total_bytes_recv: number;
  uptime_seconds: number;
  boot_time?: string;
}

export interface ProcessItem {
  pid: number;
  ppid?: number | null;
  name: string;
  exe_path?: string | null;
  cmdline?: string | null;
  username?: string | null;
  status: string;
  cpu_percent: number;
  memory_mb: number;
  memory_percent: number;
  create_time?: string | null;
  risk_score: number;
  risk_level: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_reasons: string[];
}

export interface NetworkItem {
  pid: number;
  process_name: string;
  protocol: string;
  local_ip: string;
  local_port: number;
  remote_ip: string;
  remote_port: number | string;
  state: string;
  risk_score: number;
  risk_level: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_reasons: string[];
}

export interface DefenderStatus {
  available: boolean;
  status: string;
  reason?: string | null;
  am_running_mode?: string | null;
  real_time_protection: boolean;
  antivirus_enabled: boolean;
  antispyware_enabled?: boolean;
  behavior_monitor_enabled?: boolean;
  signature_version: string;
  signature_age_days: number;
  quick_scan_age_days: number;
  engine_version?: string | null;
  recent_threats?: any[];
  last_checked?: string | null;
}

export interface FirewallProfile {
  enabled: boolean;
  default_inbound?: string;
  default_outbound?: string;
}

export interface FirewallStatus {
  available: boolean;
  status: string;
  reason?: string | null;
  profiles: Record<string, FirewallProfile>;
  all_enabled: boolean;
  last_checked?: string | null;
}

export interface ProtectionStatus {
  defender: DefenderStatus;
  firewall: FirewallStatus;
}

export interface SoftwareItem {
  name: string;
  version: string;
  publisher: string;
  install_date?: string | null;
  install_location?: string | null;
  architecture: string;
  security_status: string;
}

export interface ServiceItem {
  name: string;
  display_name: string;
  status: string;
  start_type: string;
  bin_path?: string | null;
  username?: string | null;
  suspicious: boolean;
  risk_reason?: string | null;
}

export interface StartupItem {
  name: string;
  path: string;
  source: string;
  enabled: boolean;
  suspicious: boolean;
  reasons: string[];
}

export interface TrackedFile {
  name: string;
  path: string;
  size: number;
  is_executable: boolean;
  extension: string;
  sha256?: string | null;
  last_modified?: string | null;
}

export interface FileEvent {
  event_type: 'file_created' | 'file_modified' | 'file_deleted';
  filename: string;
  path: string;
  size: number;
  sha256?: string | null;
  timestamp: string;
  severity: string;
  details: string;
}

export interface SecurityEvent {
  timestamp: string;
  severity: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  event_type: string;
  source: string;
  description: string;
  user?: string | null;
  process?: string | null;
  metadata?: Record<string, any>;
}

export interface ThreatAlert {
  id: string;
  severity: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  category: string;
  title: string;
  detection_source: string;
  evidence: Array<{ indicator: string; value: string }>;
  explanation: string;
  affected_object?: string | null;
  recommended_action: string;
  created_at: string;
}

export interface RiskContributor {
  factor: string;
  impact: number;
  type: 'penalty' | 'credit';
}

export interface RiskScore {
  score: number;
  level: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  breakdown: {
    'Process Risk': number;
    'Network Risk': number;
    'Persistence Risk': number;
    'File Risk': number;
    'Security Config': number;
  };
  contributors: RiskContributor[];
  summary: string;
}

export interface ScanRecord {
  scan_id: string;
  scan_type: 'quick' | 'process' | 'startup' | 'network' | 'file' | 'config';
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'UNAVAILABLE';
  findings_count: number;
  started_at: string;
  completed_at?: string | null;
  summary?: Record<string, any> | null;
}
