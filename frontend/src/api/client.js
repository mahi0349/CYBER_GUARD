const API_BASE_URL = 'http://127.0.0.1:8000/api';

export async function fetchHealth() {
  const response = await fetch(`${API_BASE_URL}/health`);
  if (!response.ok) {
    throw new Error(`Health check failed with status ${response.status}`);
  }
  return response.json();
}

export async function fetchEvents(limit = 50) {
  const response = await fetch(`${API_BASE_URL}/events?limit=${limit}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch events: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchEventById(id) {
  const response = await fetch(`${API_BASE_URL}/events/${id}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch event ${id}: ${response.statusText}`);
  }
  return response.json();
}

// ── Phishing & Social Engineering (Scenario A) ─────────────────────────

export async function analyzePhishing(payload) {
  const response = await fetch(`${API_BASE_URL}/analyze/phishing`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Phishing analysis failed with status ${response.status}`);
  }
  return response.json();
}

export async function fetchPhishingSamples() {
  const response = await fetch(`${API_BASE_URL}/analyze/phishing/samples`);
  if (!response.ok) {
    throw new Error(`Failed to fetch phishing samples: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchPhishingEvaluation() {
  const response = await fetch(`${API_BASE_URL}/analyze/phishing/evaluate`);
  if (!response.ok) {
    throw new Error(`Failed to fetch phishing evaluation: ${response.statusText}`);
  }
  return response.json();
}

// ── Deepfake & Impersonation (Scenario B) ─────────────────────────────

export async function analyzeDeepfakeImage(file) {
  const formData = new FormData();
  formData.append('file', file);
  const response = await fetch(`${API_BASE_URL}/analyze/deepfake`, {
    method: 'POST',
    body: formData
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Deepfake analysis failed with status ${response.status}`);
  }
  return response.json();
}

export async function analyzeImpersonation(payload) {
  const response = await fetch(`${API_BASE_URL}/analyze/impersonation`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Impersonation analysis failed with status ${response.status}`);
  }
  return response.json();
}

export async function fetchDeepfakeSamples() {
  const response = await fetch(`${API_BASE_URL}/analyze/deepfake/samples`);
  if (!response.ok) {
    throw new Error(`Failed to fetch deepfake samples: ${response.statusText}`);
  }
  return response.json();
}

// ── Account Takeover & Anomaly Detection (Scenario C) ─────────────────

export async function analyzeAccountLogs(logs) {
  const response = await fetch(`${API_BASE_URL}/analyze/account`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ logs })
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Account anomaly analysis failed with status ${response.status}`);
  }
  return response.json();
}

export async function fetchAccountSamples() {
  const response = await fetch(`${API_BASE_URL}/analyze/account/samples`);
  if (!response.ok) {
    throw new Error(`Failed to fetch account samples: ${response.statusText}`);
  }
  return response.json();
}

export async function generateSyntheticLogs(payload) {
  const response = await fetch(`${API_BASE_URL}/analyze/account/generate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Synthetic log generation failed with status ${response.status}`);
  }
  return response.json();
}

// ── SOC Command Dashboard & Telemetry (Phase 5 & 7) ───────────────────

export async function fetchDashboardMetrics() {
  const response = await fetch(`${API_BASE_URL}/dashboard/metrics`);
  if (!response.ok) {
    throw new Error(`Failed to fetch dashboard metrics: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchDashboardTimeline(limit = 40) {
  const response = await fetch(`${API_BASE_URL}/dashboard/timeline?limit=${limit}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch timeline: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchDashboardDistribution() {
  const response = await fetch(`${API_BASE_URL}/dashboard/distribution`);
  if (!response.ok) {
    throw new Error(`Failed to fetch distributions: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchHighRiskEntities() {
  const response = await fetch(`${API_BASE_URL}/dashboard/entities`);
  if (!response.ok) {
    throw new Error(`Failed to fetch risk entities: ${response.statusText}`);
  }
  return response.json();
}

export async function fetchCorrelations() {
  const response = await fetch(`${API_BASE_URL}/dashboard/correlations`);
  if (!response.ok) {
    throw new Error(`Failed to fetch correlations: ${response.statusText}`);
  }
  return response.json();
}

// ── Playbook Simulator & Containment (Phase 6) ────────────────────────

export async function fetchPlaybookCatalog() {
  const response = await fetch(`${API_BASE_URL}/playbooks/catalog`);
  if (!response.ok) {
    throw new Error(`Failed to fetch playbook catalog: ${response.statusText}`);
  }
  return response.json();
}

export async function executePlaybookAction(payload) {
  const response = await fetch(`${API_BASE_URL}/playbooks/execute`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Playbook execution failed with status ${response.status}`);
  }
  return response.json();
}

export async function fetchIncidentActions(eventId) {
  const response = await fetch(`${API_BASE_URL}/playbooks/actions/${eventId}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch actions: ${response.statusText}`);
  }
  return response.json();
}

export async function updateIncidentStatus(payload) {
  const response = await fetch(`${API_BASE_URL}/playbooks/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.detail || `Status update failed with status ${response.status}`);
  }
  return response.json();
}
