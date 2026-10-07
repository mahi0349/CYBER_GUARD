import axios from 'axios';
import {
  AgentStatus,
  SystemTelemetry,
  ProcessItem,
  NetworkItem,
  ProtectionStatus,
  SoftwareItem,
  ServiceItem,
  StartupItem,
  TrackedFile,
  FileEvent,
  SecurityEvent,
  ThreatAlert,
  RiskScore,
  ScanRecord
} from '../types/commandCenter';

export interface DeviceSummary {
  device_id: string;
  hostname: string;
  os_name: string;
  os_version: string;
  status: 'ONLINE' | 'DEGRADED' | 'OFFLINE';
  telemetry_age_seconds?: number | null;
  risk_score?: number;
  risk_level?: string;
}

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

const client = axios.create({
  baseURL: API_BASE_URL,
  headers: { 'Content-Type': 'application/json' },
  timeout: 10000,
});

export const fetchDevices = async (): Promise<DeviceSummary[]> => {
  try {
    const res = await client.get<DeviceSummary[]>('/command-center/devices');
    return res.data;
  } catch {
    return [];
  }
};

export const fetchAgentStatus = async (deviceId?: string): Promise<AgentStatus> => {
  const res = await client.get<AgentStatus>('/command-center/status', {
    params: deviceId ? { device_id: deviceId } : {}
  });
  return res.data;
};

export const fetchSystemTelemetry = async (deviceId?: string): Promise<SystemTelemetry | null> => {
  try {
    const res = await client.get('/command-center/system', {
      params: deviceId ? { device_id: deviceId } : {}
    });
    if (res.data?.status === 'UNAVAILABLE') return null;
    return res.data;
  } catch {
    return null;
  }
};

export const fetchTelemetryHistory = async (deviceId?: string): Promise<SystemTelemetry[]> => {
  try {
    const res = await client.get<SystemTelemetry[]>('/command-center/telemetry-history', {
      params: deviceId ? { device_id: deviceId } : {}
    });
    return res.data;
  } catch {
    return [];
  }
};

export const fetchProcesses = async (limit = 150, search?: string, deviceId?: string): Promise<ProcessItem[]> => {
  try {
    const params: any = { limit };
    if (search) params.search = search;
    if (deviceId) params.device_id = deviceId;
    const res = await client.get<ProcessItem[]>('/command-center/processes', { params });
    return res.data;
  } catch {
    return [];
  }
};

export const fetchNetwork = async (limit = 150, state?: string, deviceId?: string): Promise<NetworkItem[]> => {
  try {
    const params: any = { limit };
    if (state) params.state = state;
    if (deviceId) params.device_id = deviceId;
    const res = await client.get<NetworkItem[]>('/command-center/network', { params });
    return res.data;
  } catch {
    return [];
  }
};

export const fetchProtectionStatus = async (deviceId?: string): Promise<ProtectionStatus | null> => {
  try {
    const res = await client.get<ProtectionStatus>('/command-center/protection', {
      params: deviceId ? { device_id: deviceId } : {}
    });
    return res.data;
  } catch {
    return null;
  }
};

export const fetchSoftware = async (search?: string, deviceId?: string): Promise<SoftwareItem[]> => {
  try {
    const params: any = {};
    if (search) params.search = search;
    if (deviceId) params.device_id = deviceId;
    const res = await client.get<SoftwareItem[]>('/command-center/software', { params });
    return res.data;
  } catch {
    return [];
  }
};

export const fetchServices = async (status?: string, deviceId?: string): Promise<ServiceItem[]> => {
  try {
    const params: any = {};
    if (status) params.status = status;
    if (deviceId) params.device_id = deviceId;
    const res = await client.get<ServiceItem[]>('/command-center/services', { params });
    return res.data;
  } catch {
    return [];
  }
};

export const fetchStartup = async (deviceId?: string): Promise<StartupItem[]> => {
  try {
    const res = await client.get<StartupItem[]>('/command-center/startup', {
      params: deviceId ? { device_id: deviceId } : {}
    });
    return res.data;
  } catch {
    return [];
  }
};

export const fetchTrackedFiles = async (deviceId?: string): Promise<TrackedFile[]> => {
  try {
    const res = await client.get<TrackedFile[]>('/command-center/files', {
      params: deviceId ? { device_id: deviceId } : {}
    });
    return res.data;
  } catch {
    return [];
  }
};

export const fetchFileEvents = async (deviceId?: string): Promise<FileEvent[]> => {
  try {
    const res = await client.get<FileEvent[]>('/command-center/file-events', {
      params: deviceId ? { device_id: deviceId } : {}
    });
    return res.data;
  } catch {
    return [];
  }
};

export const fetchSecurityEvents = async (limit = 50, severity?: string, deviceId?: string): Promise<SecurityEvent[]> => {
  try {
    const params: any = { limit };
    if (severity) params.severity = severity;
    if (deviceId) params.device_id = deviceId;
    const res = await client.get<SecurityEvent[]>('/command-center/events', { params });
    return res.data;
  } catch {
    return [];
  }
};

export const fetchThreats = async (deviceId?: string): Promise<ThreatAlert[]> => {
  try {
    const res = await client.get<ThreatAlert[]>('/command-center/threats', {
      params: deviceId ? { device_id: deviceId } : {}
    });
    return res.data;
  } catch {
    return [];
  }
};

export const fetchScans = async (deviceId?: string): Promise<ScanRecord[]> => {
  try {
    const res = await client.get<ScanRecord[]>('/command-center/scans', {
      params: deviceId ? { device_id: deviceId } : {}
    });
    return res.data;
  } catch {
    return [];
  }
};

export const triggerScan = async (scan_type: string, deviceId?: string): Promise<ScanRecord> => {
  const res = await client.post<ScanRecord>('/command-center/scans/run', { scan_type }, {
    params: deviceId ? { device_id: deviceId } : {}
  });
  return res.data;
};

export const fetchRiskScore = async (deviceId?: string): Promise<RiskScore | null> => {
  try {
    const res = await client.get<RiskScore>('/command-center/risk', {
      params: deviceId ? { device_id: deviceId } : {}
    });
    return res.data;
  } catch {
    return null;
  }
};

export interface DeviceModeInfo {
  mode: 'SINGLE_DEVICE';
  max_allowed: number;
  is_locked: boolean;
  active_device_id: string | null;
  active_hostname: string | null;
  active_status: string;
  blocked_attempts_count: number;
  recent_blocked_attempts: Array<{
    timestamp: string;
    attempted_device_id: string;
    active_device_id: string;
    reason: string;
  }>;
}

export const fetchDeviceMode = async (): Promise<DeviceModeInfo | null> => {
  try {
    const res = await client.get<DeviceModeInfo>('/command-center/device/mode');
    return res.data;
  } catch {
    return null;
  }
};

export const disconnectDevice = async (): Promise<boolean> => {
  try {
    await client.post('/command-center/device/disconnect');
    return true;
  } catch {
    return false;
  }
};

export const getAgentScriptDownloadUrl = (): string => {
  return `${API_BASE_URL}/command-center/agent/download-script`;
};

export const getCommandCenterWebSocketUrl = (deviceId?: string): string => {
  const envApi = import.meta.env.VITE_API_URL;
  let wsUrl: string;
  if (envApi) {
    if (envApi.startsWith('https://')) {
      wsUrl = 'wss://' + envApi.slice(8);
    } else if (envApi.startsWith('http://')) {
      wsUrl = 'ws://' + envApi.slice(7);
    } else {
      wsUrl = `ws://${envApi}`;
    }
    wsUrl = `${wsUrl.replace(/\/+$/, '')}/command-center/ws`;
  } else {
    const host = window.location.hostname || 'localhost';
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    wsUrl = `${proto}//${host}:8000/api/v1/command-center/ws`;
  }

  return deviceId ? `${wsUrl}?device_id=${encodeURIComponent(deviceId)}` : wsUrl;
};

