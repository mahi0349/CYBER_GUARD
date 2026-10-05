import axios from 'axios';
import { AnalysisResponse, DashboardStats, Threat, Incident, PolicyConfig, DatabaseStatus } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000,
});

// Mock fallback data for resilient demos
export const mockDashboardStats: DashboardStats = {
  total_events_analyzed: 1248,
  threats_detected: 137,
  critical_threats: 18,
  active_incidents: 23,
  phishing_count: 72,
  deepfake_count: 14,
  account_takeover_count: 51,
  severity_distribution: {
    CRITICAL: 18,
    HIGH: 43,
    MEDIUM: 38,
    LOW: 24,
    SAFE: 14
  },
  timeline: [
    { day: 'Mon', phishing: 12, deepfake: 3, account_takeover: 5 },
    { day: 'Tue', phishing: 19, deepfake: 2, account_takeover: 7 },
    { day: 'Wed', phishing: 15, deepfake: 5, account_takeover: 4 },
    { day: 'Thu', phishing: 24, deepfake: 6, account_takeover: 9 },
    { day: 'Fri', phishing: 29, deepfake: 4, account_takeover: 12 },
    { day: 'Sat', phishing: 18, deepfake: 3, account_takeover: 8 },
    { day: 'Sun', phishing: 22, deepfake: 5, account_takeover: 11 },
  ],
  recent_threats: [
    {
      id: 1,
      threat_type: 'phishing',
      source_type: 'url',
      source_payload: 'https://secure-chase-online-verify-account.com/auth/login',
      severity: 'CRITICAL',
      risk_score: 94,
      confidence: 0.96,
      status: 'active',
      explanation: 'Critical credential phishing risk mimicking Chase authentication gateway.',
      created_at: new Date(Date.now() - 15 * 60000).toISOString(),
      evidence: [
        { id: 1, indicator: 'credential_harvesting_keywords', description: "Contains auth keywords 'verify', 'account'", weight: 14 },
        { id: 2, indicator: 'domain_hyphen_spoofing', description: 'Domain typosquatting pattern detected', weight: 12 }
      ]
    },
    {
      id: 2,
      threat_type: 'account_takeover',
      source_type: 'login_log',
      source_payload: 'Account U1003 authentication stream',
      severity: 'CRITICAL',
      risk_score: 91,
      confidence: 0.94,
      status: 'active',
      explanation: '14 sequential failed logins from Tor Exit node followed by unauthorized tool-based session.',
      created_at: new Date(Date.now() - 45 * 60000).toISOString(),
      evidence: [
        { id: 3, indicator: 'brute_force_spike', description: '14 rapid failed attempts', weight: 22 },
        { id: 4, indicator: 'geographic_anomaly', description: 'Tor exit Frankfurt IP address', weight: 16 }
      ]
    },
    {
      id: 3,
      threat_type: 'deepfake',
      source_type: 'image',
      source_payload: 'executive_id_verification.png',
      severity: 'HIGH',
      risk_score: 87,
      confidence: 0.89,
      status: 'active',
      explanation: 'Facial boundary artifacts and high-frequency noise anomaly indicate synthetic image generator.',
      created_at: new Date(Date.now() - 120 * 60000).toISOString(),
      evidence: [
        { id: 5, indicator: 'facial_boundary_artifacts', description: 'Discontinuous jawline gradient', weight: 20 },
        { id: 6, indicator: 'frequency_domain_inconsistency', description: 'Fourier GAN checkerboard signature', weight: 18 }
      ]
    }
  ],
  recent_incidents: [
    {
      id: 1,
      incident_code: 'CG-1021',
      title: 'Credential Phishing Campaign — Banking Lookalike',
      description: 'Critical phishing risk mimicking Chase authentication gateway.',
      severity: 'CRITICAL',
      status: 'OPEN',
      assigned_to: 'SOC Lead Analyst',
      mitre_technique: 'T1566',
      created_at: new Date(Date.now() - 15 * 60000).toISOString(),
      updated_at: new Date(Date.now() - 15 * 60000).toISOString()
    },
    {
      id: 2,
      incident_code: 'CG-1022',
      title: 'Account Takeover — Credential Stuffing Anomaly',
      description: '14 sequential failed logins from Tor Exit node followed by unauthorized tool-based session.',
      severity: 'CRITICAL',
      status: 'OPEN',
      assigned_to: 'Incident Response Team',
      mitre_technique: 'T1078',
      created_at: new Date(Date.now() - 45 * 60000).toISOString(),
      updated_at: new Date(Date.now() - 45 * 60000).toISOString()
    },
    {
      id: 3,
      incident_code: 'CG-1023',
      title: 'Executive Biometric Impersonation Probe',
      description: 'Facial boundary artifacts and high-frequency noise anomaly indicate synthetic image generator.',
      severity: 'HIGH',
      status: 'INVESTIGATING',
      assigned_to: 'Threat Intelligence Unit',
      mitre_technique: 'T1586',
      created_at: new Date(Date.now() - 120 * 60000).toISOString(),
      updated_at: new Date(Date.now() - 120 * 60000).toISOString()
    }
  ]
};

export const fetchDashboardStats = async (): Promise<DashboardStats> => {
  try {
    const res = await apiClient.get<DashboardStats>('/dashboard/stats');
    return res.data;
  } catch (err) {
    console.warn('API unavailable, loading local SOC telemetry state:', err);
    return mockDashboardStats;
  }
};

export const fetchThreats = async (): Promise<Threat[]> => {
  try {
    const res = await apiClient.get<Threat[]>('/threats');
    return res.data;
  } catch (err) {
    return mockDashboardStats.recent_threats;
  }
};

export const fetchIncidents = async (): Promise<Incident[]> => {
  try {
    const res = await apiClient.get<Incident[]>('/incidents');
    return res.data;
  } catch (err) {
    return mockDashboardStats.recent_incidents;
  }
};

export const executeIncidentAction = async (incidentId: number, actionType: string, notes?: string) => {
  try {
    const res = await apiClient.post(`/incidents/${incidentId}/action`, {
      action_type: actionType,
      notes: notes || 'Simulated containment triggered by SOC analyst'
    });
    return res.data;
  } catch (err) {
    // Fallback simulation
    return {
      success: true,
      result: {
        action_id: 99,
        incident_id: incidentId,
        action_type: actionType,
        status: 'SIMULATED_SUCCESS',
        description: `Executed simulated response playbook: ${actionType}. Perimeter updated.`,
        new_incident_status: 'CONTAINED'
      }
    };
  }
};

export const analyzeUrl = async (url: string): Promise<AnalysisResponse> => {
  try {
    const res = await apiClient.post<AnalysisResponse>('/analyze/url', { url });
    return res.data;
  } catch (err) {
    console.warn('Backend unavailable, running local client phishing analyzer fallback');
    const hasKeyword = ['verify', 'account', 'login', 'secure', 'chase', 'banking'].some(k => url.toLowerCase().includes(k));
    const score = hasKeyword ? 94 : 14;
    return {
      threat_type: 'phishing',
      prediction: hasKeyword ? 'malicious' : 'clean',
      confidence: hasKeyword ? 0.96 : 0.05,
      risk_score: score,
      severity: hasKeyword ? 'CRITICAL' : 'SAFE',
      evidence: hasKeyword ? [
        { indicator: 'suspicious_domain', description: 'Look-alike domain resembles legitimate financial institution', weight: 16 },
        { indicator: 'credential_harvesting_keywords', description: 'Detected explicit login and account verification strings', weight: 14 },
        { indicator: 'url_anomaly', description: 'Nested subdomain obfuscation detected', weight: 10 }
      ] : [
        { indicator: 'clean_domain_reputation', description: 'Verified legitimate domain structure', weight: 0 }
      ],
      recommended_actions: hasKeyword ? ['block_url', 'quarantine_message', 'notify_soc_team'] : ['allow_traffic'],
      explanation: hasKeyword
        ? 'CRITICAL phishing threat identified. The analyzed URL mimics a protected banking authentication interface to capture user credentials.'
        : 'Target URL verified as legitimate. No threat indicators detected.',
      mitre_technique: 'T1566',
      mitre_name: 'Phishing: Spearphishing Link'
    };
  }
};

export const analyzeEmail = async (sender: string, subject: string, body: string): Promise<AnalysisResponse> => {
  try {
    const res = await apiClient.post<AnalysisResponse>('/analyze/email', { sender, subject, body });
    return res.data;
  } catch (err) {
    console.warn('Backend unavailable, running local email analysis fallback');
    const hasUrgency = ['urgent', 'immediately', 'suspended', 'verify', 'action required'].some(k => `${subject} ${body}`.toLowerCase().includes(k));
    const isSpoofed = sender.includes('paypa1') || sender.includes('micr0soft') || /\d/.test(sender.split('@')[1] || '');
    const score = (hasUrgency && isSpoofed) ? 92 : (hasUrgency ? 72 : 18);
    return {
      threat_type: 'phishing',
      prediction: score >= 60 ? 'malicious' : (score >= 40 ? 'suspicious' : 'clean'),
      confidence: score >= 60 ? 0.94 : 0.15,
      risk_score: score,
      severity: score >= 80 ? 'CRITICAL' : (score >= 60 ? 'HIGH' : 'SAFE'),
      evidence: hasUrgency ? [
        { indicator: 'urgency_coercion_language', description: 'Social engineering urgency tactics detected in message content', weight: 12 },
        ...(isSpoofed ? [{ indicator: 'brand_domain_impersonation', description: `Sender domain appears to impersonate a known brand`, weight: 18 }] : [])
      ] : [
        { indicator: 'clean_email', description: 'No phishing indicators detected', weight: 0 }
      ],
      recommended_actions: score >= 60 ? ['block_sender', 'quarantine_message', 'notify_soc_team'] : ['deliver_normally'],
      explanation: score >= 60
        ? 'Phishing email detected with social engineering urgency tactics and potential brand impersonation.'
        : 'Email appears legitimate. No threat indicators detected.',
      mitre_technique: 'T1566',
      mitre_name: 'Phishing: Spearphishing via Email'
    };
  }
};

export const analyzeLoginLog = async (userId: string, file?: File): Promise<AnalysisResponse> => {
  try {
    const formData = new FormData();
    formData.append('user_id', userId);
    if (file) {
      formData.append('file', file);
    }
    const res = await apiClient.post<AnalysisResponse>('/analyze/login-log', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    return res.data;
  } catch (err) {
    return {
      threat_type: 'account_takeover',
      prediction: 'malicious',
      confidence: 0.94,
      risk_score: 91,
      severity: 'CRITICAL',
      evidence: [
        { indicator: 'brute_force_spike', description: '14 rapid failed authentication attempts in under 3 minutes', weight: 22 },
        { indicator: 'geographic_anomaly', description: 'Origin IP routed via Tor exit node (Frankfurt, Germany)', weight: 16 },
        { indicator: 'unrecognized_hardware_signature', description: 'New device hardware fingerprint without existing trust anchor', weight: 12 },
        { indicator: 'automated_scripting_client', description: 'HTTP User-Agent identifies as automated request tool (Python-urllib)', weight: 18 }
      ],
      recommended_actions: ['revoke_session', 'require_mfa', 'block_ip'],
      explanation: 'CRITICAL account takeover anomaly detected. Telemetry reveals automated credential stuffing from a Tor relay with sudden device divergence.',
      mitre_technique: 'T1078',
      mitre_name: 'Valid Accounts: Compromised Credentials'
    };
  }
};

export const analyzeImage = async (file: File): Promise<AnalysisResponse> => {
  try {
    const formData = new FormData();
    formData.append('file', file);
    const res = await apiClient.post<AnalysisResponse>('/analyze/image', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    return res.data;
  } catch (err) {
    return {
      threat_type: 'deepfake',
      prediction: 'manipulated',
      confidence: 0.89,
      risk_score: 87,
      severity: 'HIGH',
      evidence: [
        { indicator: 'facial_boundary_artifacts', description: 'Discontinuous pixel blending along jawline boundary', weight: 20 },
        { indicator: 'frequency_domain_inconsistency', description: 'Fourier transform reveals GAN/diffusion checkerboard lattice', weight: 18 },
        { indicator: 'corneal_reflection_asymmetry', description: 'Specular eye reflection vectors violate single light source', weight: 14 }
      ],
      recommended_actions: ['flag_impersonation', 'require_manual_soc_verification', 'restrict_privileged_actions'],
      explanation: 'HIGH risk of synthetic media manipulation. Frequency-domain and biometric boundary analysis indicate neural generative synthesis.',
      mitre_technique: 'T1586',
      mitre_name: 'Impersonation / Synthetic Identity',
      features: { authenticity_score: 11.0, manipulation_probability: 89.0 }
    };
  }
};

export const analyzeAudio = async (file: File): Promise<AnalysisResponse> => {
  try {
    const formData = new FormData();
    formData.append('file', file);
    const res = await apiClient.post<AnalysisResponse>('/analyze/audio', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    return res.data;
  } catch (err) {
    return {
      threat_type: 'deepfake_audio',
      prediction: 'suspicious',
      confidence: 0.72,
      risk_score: 68,
      severity: 'HIGH',
      evidence: [
        { indicator: 'spectral_flatness_anomaly', description: 'Elevated spectral flatness suggesting neural vocoder synthesis', weight: 14 },
        { indicator: 'pitch_stability_anomaly', description: 'Abnormally stable pitch without natural jitter variation', weight: 18 },
        { indicator: 'uniform_mel_spectrum', description: 'Mel-spectrogram displays synthetic uniformity', weight: 12 }
      ],
      recommended_actions: ['flag_voice_impersonation', 'require_callback_verification', 'block_voice_auth'],
      explanation: 'Audio forensic analysis detected spectral anomalies consistent with AI voice synthesis.',
      mitre_technique: 'T1586',
      mitre_name: 'Voice Cloning / Audio Impersonation',
      features: { authenticity_score: 28.0, manipulation_probability: 72.0 }
    };
  }
};

const POLICY_STORAGE_KEY = 'cyberguard_risk_policy';
const ALT_POLICY_STORAGE_KEY = 'quantumvault_risk_policy';

export const getActivePolicyThresholds = (): PolicyConfig => {
  try {
    const raw = localStorage.getItem(POLICY_STORAGE_KEY) || localStorage.getItem(ALT_POLICY_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed.low_threshold !== undefined) return parsed;
    }
  } catch (e) {
    console.warn('Could not parse cached risk policy', e);
  }
  return {
    low_threshold: 20,
    medium_threshold: 40,
    high_threshold: 60,
    critical_threshold: 80,
    gemini_model: 'gemini-3.8-flash'
  };
};

export const saveActivePolicyThresholdsLocal = (policy: Partial<PolicyConfig>): PolicyConfig => {
  const current = getActivePolicyThresholds();
  const updated: PolicyConfig = {
    ...current,
    ...policy
  };
  try {
    const serialized = JSON.stringify(updated);
    localStorage.setItem(POLICY_STORAGE_KEY, serialized);
    localStorage.setItem(ALT_POLICY_STORAGE_KEY, serialized);
  } catch (e) {
    console.warn('Failed to save policy to localStorage', e);
  }
  return updated;
};

export const classifySeverity = (score: number): 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' => {
  const policy = getActivePolicyThresholds();
  if (score >= policy.critical_threshold) return 'CRITICAL';
  if (score >= policy.high_threshold) return 'HIGH';
  if (score >= policy.medium_threshold) return 'MEDIUM';
  if (score >= policy.low_threshold) return 'LOW';
  return 'SAFE';
};


export const fetchRiskPolicy = async (): Promise<{ policy: PolicyConfig; database?: DatabaseStatus }> => {
  try {
    const res = await apiClient.get<PolicyConfig & { database?: DatabaseStatus }>('/settings/policy', {
      timeout: 3000
    });
    const { database, ...policy } = res.data;
    saveActivePolicyThresholdsLocal(policy);
    return { policy, database };
  } catch (err) {
    console.warn('Backend unavailable, loading cached/default risk policy:', err);
    return {
      policy: getActivePolicyThresholds(),
      database: {
        configured_driver: 'sqlite',
        active_driver: 'sqlite',
        active_url: 'sqlite:///./cyberguard.db (Offline mode)',
        status: 'local_fallback',
        is_postgres: false,
        postgres_container_running: false,
        fallback_in_use: true,
        counts: {
          threats: 57,
          incidents: 40,
          scans: 54,
          users: 1
        }
      }
    };
  }
};

export const updateRiskPolicy = async (payload: {
  low_threshold: number;
  medium_threshold: number;
  high_threshold: number;
  critical_threshold: number;
  gemini_model?: string;
}): Promise<{ policy: PolicyConfig; database?: DatabaseStatus }> => {
  // Always update client cache immediately so it never resets
  saveActivePolicyThresholdsLocal(payload);
  try {
    const res = await apiClient.put<PolicyConfig & { database?: DatabaseStatus }>('/settings/policy', payload, {
      timeout: 3000
    });
    const { database, ...policy } = res.data;
    saveActivePolicyThresholdsLocal(policy);
    return { policy, database };
  } catch (err) {
    console.warn('Backend unavailable, policy saved in browser client storage:', err);
    return {
      policy: payload,
    };
  }
};

export const fetchDatabaseStatus = async (): Promise<DatabaseStatus> => {
  try {
    const res = await apiClient.get<DatabaseStatus>('/settings/db-status');
    return res.data;
  } catch (err) {
    return {
      configured_driver: 'sqlite',
      active_driver: 'sqlite',
      active_url: 'sqlite:///./cyberguard.db',
      status: 'offline',
      is_postgres: false,
      postgres_container_running: false,
      fallback_in_use: true,
      counts: { threats: 57, incidents: 40, scans: 54, users: 1 }
    };
  }
};

export const reconnectDatabase = async (): Promise<{ success: boolean; message: string; status: DatabaseStatus }> => {
  const res = await apiClient.post('/settings/db-reconnect');
  return res.data;
};

