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

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

const client = axios.create({
  baseURL: API_BASE_URL,
  headers: { 'Content-Type': 'application/json' },
  timeout: 10000,
});

export const fetchAgentStatus = async (): Promise<AgentStatus> => {
  const res = await client.get<AgentStatus>('/command-center/status');
  return res.data;
};

export const fetchSystemTelemetry = async (): Promise<SystemTelemetry | null> => {
  try {
    const res = await client.get('/command-center/system');
    if (res.data?.status === 'UNAVAILABLE') return null;
    return res.data;
  } catch {
    return null;
  }
};

export const fetchTelemetryHistory = async (): Promise<SystemTelemetry[]> => {
  try {
    const res = await client.get<SystemTelemetry[]>('/command-center/telemetry-history');
    return res.data;
  } catch {
    return [];
  }
};

export const fetchProcesses = async (limit = 150, search?: string): Promise<ProcessItem[]> => {
  try {
    const res = await client.get<ProcessItem[]>('/command-center/processes', {
      params: { limit, search }
    });
    return res.data;
  } catch {
    return [];
  }
};

export const fetchNetwork = async (limit = 150, state?: string): Promise<NetworkItem[]> => {
  try {
    const res = await client.get<NetworkItem[]>('/command-center/network', {
      params: { limit, state }
    });
    return res.data;
  } catch {
    return [];
  }
};

export const fetchProtectionStatus = async (): Promise<ProtectionStatus | null> => {
  try {
    const res = await client.get<ProtectionStatus>('/command-center/protection');
    return res.data;
  } catch {
    return null;
  }
};

export const fetchSoftware = async (search?: string): Promise<SoftwareItem[]> => {
  try {
    const res = await client.get<SoftwareItem[]>('/command-center/software', {
      params: { search }
    });
    return res.data;
  } catch {
    return [];
  }
};

export const fetchServices = async (status?: string): Promise<ServiceItem[]> => {
  try {
    const res = await client.get<ServiceItem[]>('/command-center/services', {
      params: { status }
    });
    return res.data;
  } catch {
    return [];
  }
};

export const fetchStartup = async (): Promise<StartupItem[]> => {
  try {
    const res = await client.get<StartupItem[]>('/command-center/startup');
    return res.data;
  } catch {
    return [];
  }
};

export const fetchTrackedFiles = async (): Promise<TrackedFile[]> => {
  try {
    const res = await client.get<TrackedFile[]>('/command-center/files');
    return res.data;
  } catch {
    return [];
  }
};

export const fetchFileEvents = async (): Promise<FileEvent[]> => {
  try {
    const res = await client.get<FileEvent[]>('/command-center/file-events');
    return res.data;
  } catch {
    return [];
  }
};

export const fetchSecurityEvents = async (limit = 50, severity?: string): Promise<SecurityEvent[]> => {
  try {
    const res = await client.get<SecurityEvent[]>('/command-center/events', {
      params: { limit, severity }
    });
    return res.data;
  } catch {
    return [];
  }
};

export const fetchThreats = async (): Promise<ThreatAlert[]> => {
  try {
    const res = await client.get<ThreatAlert[]>('/command-center/threats');
    return res.data;
  } catch {
    return [];
  }
};

export const fetchScans = async (): Promise<ScanRecord[]> => {
  try {
    const res = await client.get<ScanRecord[]>('/command-center/scans');
    return res.data;
  } catch {
    return [];
  }
};

export const triggerScan = async (scan_type: string): Promise<ScanRecord> => {
  const res = await client.post<ScanRecord>('/command-center/scans/run', { scan_type });
  return res.data;
};

export const fetchRiskScore = async (): Promise<RiskScore | null> => {
  try {
    const res = await client.get<RiskScore>('/command-center/risk');
    return res.data;
  } catch {
    return null;
  }
};

export const getCommandCenterWebSocketUrl = (): string => {
  const host = window.location.hostname || 'localhost';
  return `ws://${host}:8000/api/v1/command-center/ws`;
};
