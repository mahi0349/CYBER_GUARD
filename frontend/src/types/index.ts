export interface EvidenceItem {
  indicator: string;
  description: string;
  weight: number;
}

export interface AnalysisResponse {
  threat_type: 'phishing' | 'deepfake' | 'deepfake_audio' | 'account_takeover' | 'email_authenticity';
  prediction: 'malicious' | 'suspicious' | 'clean' | 'manipulated' | 'authentic';
  confidence: number;
  risk_score: number;
  severity: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  evidence: EvidenceItem[];
  recommended_actions: string[];
  explanation?: string;
  mitre_technique?: string;
  mitre_name?: string;
  features?: Record<string, any>;
  threat_id?: number;
  incident_id?: number;
}

// Email Authenticity Analysis types
export interface EmailAuthFinding {
  check: string;
  status: 'pass' | 'fail' | 'warn' | 'info' | 'error';
  detail: string;
  weight: number;
}

export interface EmailAuthResult {
  score: number;
  level: 'Safe' | 'Low' | 'Medium' | 'High' | 'Critical';
  findings: EmailAuthFinding[];
  evidence: Record<string, any>;
  recommended_actions: string[];
  explanation?: string;
  threat_id?: number;
  incident_id?: number;
}

export interface Threat {
  id: number;
  threat_type: string;
  source_type: string;
  source_payload?: string;
  severity: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  risk_score: number;
  confidence: number;
  status: string;
  explanation?: string;
  created_at: string;
  evidence: {
    id: number;
    indicator: string;
    description: string;
    weight: number;
  }[];
}

export interface Incident {
  id: number;
  threat_id?: number;
  incident_code: string;
  title: string;
  description: string;
  severity: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED';
  assigned_to: string;
  mitre_technique: string;
  created_at: string;
  updated_at: string;
}

export interface DashboardStats {
  total_events_analyzed: number;
  threats_detected: number;
  critical_threats: number;
  active_incidents: number;
  phishing_count: number;
  deepfake_count: number;
  account_takeover_count: number;
  severity_distribution: Record<string, number>;
  timeline: {
    day: string;
    phishing: number;
    deepfake: number;
    account_takeover: number;
  }[];
  recent_threats: Threat[];
  recent_incidents: Incident[];
}

export interface PolicyConfig {
  low_threshold: number;
  medium_threshold: number;
  high_threshold: number;
  critical_threshold: number;
  gemini_model?: string;
  updated_at?: string;
}

export interface DatabaseStatus {
  configured_driver: string;
  active_driver: string;
  active_url: string;
  status: string;
  is_postgres: boolean;
  postgres_container_running: boolean;
  fallback_in_use: boolean;
  counts: {
    threats: number;
    incidents: number;
    scans: number;
    users: number;
  };
}
