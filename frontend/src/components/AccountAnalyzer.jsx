import React, { useState, useEffect } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock,
  Compass,
  Cpu,
  Globe,
  HardDrive,
  Key,
  Layers,
  Loader2,
  Lock,
  MapPin,
  Maximize2,
  Plane,
  Play,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  UserCheck,
  Users,
  UserX,
  Zap
} from 'lucide-react';
import {
  analyzeAccountLogs,
  fetchAccountSamples,
  generateSyntheticLogs
} from '../api/client';

// ── Badges & Color Helpers ──────────────────────────────────────────────

const riskBadgeClass = (level) => {
  const map = {
    Safe: 'badge-safe',
    Low: 'badge-low',
    Medium: 'badge-medium',
    High: 'badge-high',
    Critical: 'badge-critical'
  };
  return `badge ${map[level] || 'badge-low'}`;
};

const riskColor = (level) => {
  const map = {
    Safe: '#10b981',
    Low: '#38bdf8',
    Medium: '#f59e0b',
    High: '#f87171',
    Critical: '#ef4444'
  };
  return map[level] || '#94a3b8';
};

// ── Risk Gauge SVG ──────────────────────────────────────────────────────

function RiskGauge({ score, level }) {
  const pct = Math.min(100, Math.max(0, score));
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (pct / 100) * circumference;

  return (
    <div style={{ textAlign: 'center', padding: '12px 0' }}>
      <svg width="180" height="110" viewBox="0 0 180 110">
        <path
          d="M 10 100 A 70 70 0 0 1 170 100"
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth="12"
          strokeLinecap="round"
        />
        <path
          d="M 10 100 A 70 70 0 0 1 170 100"
          fill="none"
          stroke={riskColor(level)}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${circumference / 2}`}
          strokeDashoffset={dashOffset / 2}
          style={{ transition: 'stroke-dashoffset 1.2s ease-out, stroke 0.6s ease' }}
        />
        <text x="90" y="80" textAnchor="middle" fill="#ffffff" fontSize="28" fontWeight="800">
          {score.toFixed(1)}
        </text>
        <text x="90" y="98" textAnchor="middle" fill={riskColor(level)} fontSize="13" fontWeight="700">
          {level}
        </text>
      </svg>
    </div>
  );
}

export default function AccountAnalyzer({ onAnalysisComplete }) {
  const [activeTab, setActiveTab] = useState('scenarios'); // 'scenarios' | 'generator' | 'table'
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [samples, setSamples] = useState([]);
  const [currentLogs, setCurrentLogs] = useState([]);
  const [currentScenarioName, setCurrentScenarioName] = useState('');
  const [result, setResult] = useState(null);

  // Generator form
  const [genForm, setGenForm] = useState({
    username: 'alex.mercer@cyberguard.internal',
    count: 8,
    anomaly_type: 'impossible_travel'
  });
  const [generating, setGenerating] = useState(false);

  // Load samples on mount
  useEffect(() => {
    fetchAccountSamples()
      .then((data) => {
        setSamples(data);
        if (data && data.length > 0) {
          // Default to the first scenario (Impossible Travel)
          loadScenario(data[0]);
        }
      })
      .catch((err) => {
        console.error('Failed to fetch account samples:', err);
      });
  }, []);

  const loadScenario = (scenario) => {
    setCurrentScenarioName(scenario.name);
    setCurrentLogs(scenario.logs);
    setResult(null);
    setError(null);
  };

  const handleRunAnalysis = async () => {
    if (!currentLogs || currentLogs.length === 0) {
      setError('Please select or generate authentication logs before analyzing.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await analyzeAccountLogs(currentLogs);
      setResult(res);
      if (onAnalysisComplete) {
        onAnalysisComplete(res);
      }
    } catch (err) {
      setError(err.message || 'Detection failed. Please check backend server.');
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateLogs = async () => {
    setGenerating(true);
    setError(null);
    try {
      const res = await generateSyntheticLogs(genForm);
      setCurrentLogs(res.logs);
      setCurrentScenarioName(`Dynamic Stream: ${genForm.anomaly_type.replace('_', ' ').toUpperCase()}`);
      setActiveTab('table');
      setResult(null);
    } catch (err) {
      setError(err.message || 'Failed to generate logs');
    } finally {
      setGenerating(false);
    }
  };

  // Extract travel events if present in result metadata
  const travelEvents = result?.metadata?.impossible_travel_events || [];
  const bruteEvents = result?.metadata?.brute_force_events || [];
  const deviceAnomalies = result?.metadata?.device_anomalies || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Header Banner */}
      <div className="card" style={{
        background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.9), rgba(30, 41, 59, 0.7))',
        borderColor: 'rgba(56, 189, 248, 0.25)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '46px',
            height: '46px',
            borderRadius: '12px',
            background: 'linear-gradient(135deg, #0ea5e9, #6366f1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 16px rgba(14, 165, 233, 0.4)'
          }}>
            <UserX size={24} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0 }}>
                Scenario C: Account Takeover & Anomaly Detection
              </h2>
              <span className="badge badge-critical" style={{ fontSize: '0.65rem' }}>
                HYBRID AI & FORENSICS
              </span>
            </div>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: '4px 0 0 0' }}>
              Real-time physical geo-velocity validation (Haversine), brute-force burst detection, device novelty heuristics & Isolation Forest ML.
            </p>
          </div>
        </div>

        {/* Action Button */}
        <button
          onClick={handleRunAnalysis}
          disabled={loading || currentLogs.length === 0}
          className="btn btn-primary"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '10px 22px',
            fontSize: '0.88rem',
            background: 'linear-gradient(135deg, #0ea5e9, #3b82f6)',
            boxShadow: '0 0 18px rgba(14, 165, 233, 0.4)'
          }}
        >
          {loading ? <Loader2 size={16} className="spin" /> : <Zap size={16} />}
          {loading ? 'Executing Anomaly Engine...' : 'Run Anomaly Detection Engine'}
        </button>
      </div>

      {/* Mode Navigation Tabs */}
      <div style={{
        display: 'flex',
        gap: '10px',
        borderBottom: '1px solid var(--border-subtle)',
        paddingBottom: '10px'
      }}>
        <button
          onClick={() => setActiveTab('scenarios')}
          style={{
            background: activeTab === 'scenarios' ? 'rgba(14, 165, 233, 0.15)' : 'transparent',
            color: activeTab === 'scenarios' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            border: activeTab === 'scenarios' ? '1px solid var(--accent-cyan)' : '1px solid transparent',
            borderRadius: '8px',
            padding: '8px 16px',
            fontSize: '0.82rem',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}
        >
          <ShieldAlert size={14} />
          Attack & Baseline Presets ({samples.length})
        </button>

        <button
          onClick={() => setActiveTab('generator')}
          style={{
            background: activeTab === 'generator' ? 'rgba(14, 165, 233, 0.15)' : 'transparent',
            color: activeTab === 'generator' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            border: activeTab === 'generator' ? '1px solid var(--accent-cyan)' : '1px solid transparent',
            borderRadius: '8px',
            padding: '8px 16px',
            fontSize: '0.82rem',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}
        >
          <RefreshCw size={14} />
          Synthetic Log Generator
        </button>

        <button
          onClick={() => setActiveTab('table')}
          style={{
            background: activeTab === 'table' ? 'rgba(14, 165, 233, 0.15)' : 'transparent',
            color: activeTab === 'table' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            border: activeTab === 'table' ? '1px solid var(--accent-cyan)' : '1px solid transparent',
            borderRadius: '8px',
            padding: '8px 16px',
            fontSize: '0.82rem',
            fontWeight: 600,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}
        >
          <Terminal size={14} />
          Current Log Stream ({currentLogs.length} events)
        </button>
      </div>

      {/* Error alert */}
      {error && (
        <div style={{
          backgroundColor: 'rgba(239, 68, 68, 0.12)',
          border: '1px solid rgba(239, 68, 68, 0.4)',
          borderRadius: '8px',
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          color: '#fca5a5',
          fontSize: '0.85rem'
        }}>
          <AlertTriangle size={18} color="#ef4444" />
          <span>{error}</span>
        </div>
      )}

      {/* Tab 1: Curated Scenarios */}
      {activeTab === 'scenarios' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(270px, 1fr))', gap: '14px' }}>
          {samples.map((s) => {
            const isSelected = currentScenarioName === s.name;
            return (
              <div
                key={s.id}
                onClick={() => loadScenario(s)}
                className="card card-interactive"
                style={{
                  padding: '16px',
                  borderColor: isSelected ? 'var(--accent-cyan)' : 'var(--border-subtle)',
                  backgroundColor: isSelected ? 'rgba(14, 165, 233, 0.08)' : 'var(--bg-card)',
                  cursor: 'pointer',
                  position: 'relative'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                  <span className={riskBadgeClass(s.expected_risk)} style={{ fontSize: '0.65rem' }}>
                    {s.expected_risk.toUpperCase()}
                  </span>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                    {s.log_count} events
                  </span>
                </div>
                <h4 style={{ fontSize: '0.92rem', fontWeight: 600, margin: '0 0 6px 0' }}>
                  {s.name}
                </h4>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.4, margin: '0 0 10px 0' }}>
                  {s.description}
                </p>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                  <UserCheck size={12} />
                  <span>Target: {s.target_user}</span>
                </div>
                {isSelected && (
                  <div style={{
                    marginTop: '10px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    color: 'var(--accent-cyan)',
                    fontSize: '0.72rem',
                    fontWeight: 600
                  }}>
                    <CheckCircle2 size={13} /> Active in buffer
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Tab 2: Synthetic Generator */}
      {activeTab === 'generator' && (
        <div className="card" style={{ padding: '20px' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, margin: '0 0 14px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Cpu size={18} color="var(--accent-cyan)" />
            Dynamic Synthetic Auth Log Generator
          </h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '16px' }}>
            Configure and synthesize custom authentication log sequences with targeted anomaly injections.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginBottom: '20px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Target Username
              </label>
              <input
                type="text"
                value={genForm.username}
                onChange={(e) => setGenForm({ ...genForm, username: e.target.value })}
                className="input"
                style={{ width: '100%' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Log Event Count (2 - 30)
              </label>
              <input
                type="number"
                min="2"
                max="30"
                value={genForm.count}
                onChange={(e) => setGenForm({ ...genForm, count: parseInt(e.target.value) || 8 })}
                className="input"
                style={{ width: '100%' }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                Injected Threat Pattern
              </label>
              <select
                value={genForm.anomaly_type}
                onChange={(e) => setGenForm({ ...genForm, anomaly_type: e.target.value })}
                className="input"
                style={{ width: '100%' }}
              >
                <option value="impossible_travel">Impossible Travel (Speed Anomaly)</option>
                <option value="brute_force">Brute Force / Password Spray</option>
                <option value="new_device">New Device Hijack (MFA Missing)</option>
                <option value="normal">Clean Baseline (Normal Behavior)</option>
              </select>
            </div>
          </div>

          <button
            onClick={handleGenerateLogs}
            disabled={generating}
            className="btn btn-primary"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}
          >
            {generating ? <Loader2 size={16} className="spin" /> : <RefreshCw size={16} />}
            Generate and Load Log Stream
          </button>
        </div>
      )}

      {/* Tab 3: Current Log Stream Table */}
      <div className="card" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{
          padding: '14px 18px',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          backgroundColor: 'rgba(15, 23, 42, 0.4)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Terminal size={16} color="var(--accent-cyan)" />
            <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>
              Active Log Stream: {currentScenarioName || 'Custom'}
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              ({currentLogs.length} events)
            </span>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={handleRunAnalysis}
              disabled={loading || currentLogs.length === 0}
              className="btn btn-secondary"
              style={{ fontSize: '0.78rem', padding: '6px 12px', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Play size={13} /> Run Detector
            </button>
          </div>
        </div>

        {/* Scrollable Table */}
        <div style={{ overflowX: 'auto', maxHeight: '340px' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.76rem' }}>
            <thead>
              <tr style={{ backgroundColor: 'rgba(15, 23, 42, 0.6)', borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', color: 'var(--text-muted)' }}>
                <th style={{ padding: '10px 14px' }}>#</th>
                <th style={{ padding: '10px 14px' }}>Status</th>
                <th style={{ padding: '10px 14px' }}>Timestamp (UTC)</th>
                <th style={{ padding: '10px 14px' }}>User</th>
                <th style={{ padding: '10px 14px' }}>Location</th>
                <th style={{ padding: '10px 14px' }}>IP Address</th>
                <th style={{ padding: '10px 14px' }}>Device & MFA</th>
              </tr>
            </thead>
            <tbody>
              {currentLogs.map((log, idx) => {
                const isFail = log.status.toUpperCase() === 'FAILURE';
                return (
                  <tr
                    key={idx}
                    style={{
                      borderBottom: '1px solid rgba(255,255,255,0.04)',
                      backgroundColor: isFail ? 'rgba(239, 68, 68, 0.05)' : 'transparent'
                    }}
                  >
                    <td style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>{idx + 1}</td>
                    <td style={{ padding: '10px 14px' }}>
                      <span className={`badge ${isFail ? 'badge-critical' : 'badge-safe'}`} style={{ fontSize: '0.62rem' }}>
                        {log.status}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                      {typeof log.timestamp === 'string' ? log.timestamp.replace('T', ' ').slice(0, 19) : new Date(log.timestamp).toISOString().replace('T', ' ').slice(0, 19)}
                    </td>
                    <td style={{ padding: '10px 14px', fontWeight: 600 }}>{log.username}</td>
                    <td style={{ padding: '10px 14px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                        <MapPin size={12} color="var(--accent-cyan)" />
                        <span>{log.city || 'Unknown'}, {log.country || 'N/A'}</span>
                      </div>
                    </td>
                    <td style={{ padding: '10px 14px', fontFamily: 'monospace' }}>{log.ip_address}</td>
                    <td style={{ padding: '10px 14px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', maxWidth: '140px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {log.device_fingerprint}
                        </span>
                        {log.mfa_used ? (
                          <span style={{ color: '#34d399', display: 'flex', alignItems: 'center', gap: '2px', fontSize: '0.65rem' }}>
                            <ShieldCheck size={12} /> MFA
                          </span>
                        ) : (
                          <span style={{ color: '#f87171', display: 'flex', alignItems: 'center', gap: '2px', fontSize: '0.65rem' }}>
                            <AlertTriangle size={12} /> No MFA
                          </span>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Results Section */}
      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
            gap: '16px'
          }}>
            {/* Threat Gauge & Classification Card */}
            <div className="card" style={{ padding: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                    Authentication Threat Score
                  </span>
                  <span className={riskBadgeClass(result.risk_level)}>
                    {result.risk_level}
                  </span>
                </div>
                <RiskGauge score={result.risk_score} level={result.risk_level} />
              </div>

              <div style={{
                backgroundColor: 'rgba(15, 23, 42, 0.6)',
                borderRadius: '8px',
                padding: '12px',
                border: '1px solid var(--border-subtle)',
                marginTop: '10px'
              }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                  Classification
                </div>
                <div style={{ fontSize: '0.92rem', fontWeight: 700, color: riskColor(result.risk_level) }}>
                  {result.threat_classification}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  Target User: <strong>{result.target_identity}</strong>
                </div>
              </div>
            </div>

            {/* Geo-Velocity / Impossible Travel Visual Card */}
            {travelEvents.length > 0 ? (
              <div className="card" style={{
                padding: '20px',
                borderColor: 'rgba(239, 68, 68, 0.4)',
                background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.08), rgba(15, 23, 42, 0.8))'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
                  <Plane size={18} color="#ef4444" />
                  <h4 style={{ fontSize: '0.95rem', fontWeight: 700, margin: 0, color: '#f87171' }}>
                    Impossible Travel Velocity Violation
                  </h4>
                </div>

                {travelEvents.map((evt, idx) => (
                  <div key={idx} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    {/* Route Visual */}
                    <div style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      backgroundColor: 'rgba(0,0,0,0.3)',
                      padding: '12px 16px',
                      borderRadius: '8px',
                      border: '1px solid rgba(239,68,68,0.2)'
                    }}>
                      <div style={{ textAlign: 'left' }}>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>ORIGIN</div>
                        <div style={{ fontSize: '0.95rem', fontWeight: 700 }}>{evt.origin_city}</div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>{evt.origin_country}</div>
                      </div>

                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '2px' }}>
                        <span style={{ fontSize: '0.72rem', color: '#f87171', fontWeight: 700 }}>
                          {evt.velocity_kmh.toLocaleString()} km/h
                        </span>
                        <div style={{ width: '80px', height: '2px', background: 'linear-gradient(90deg, #38bdf8, #ef4444)' }} />
                        <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
                          {evt.distance_km.toLocaleString()} km in {evt.time_delta_minutes}m
                        </span>
                      </div>

                      <div style={{ textAlign: 'right' }}>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>DESTINATION</div>
                        <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f87171' }}>{evt.dest_city}</div>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>{evt.dest_country}</div>
                      </div>
                    </div>

                    {/* Speed Comparison Scale */}
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                      Calculated travel speed is <strong>{(evt.velocity_kmh / 850).toFixed(1)}x faster</strong> than commercial jet airliners (850 km/h). {evt.is_supersonic && 'Travel is physically supersonic, confirming remote credential sharing or stolen web session token.'}
                    </div>
                  </div>
                ))}
              </div>
            ) : bruteEvents.length > 0 ? (
              <div className="card" style={{
                padding: '20px',
                borderColor: 'rgba(239, 68, 68, 0.4)',
                background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.08), rgba(15, 23, 42, 0.8))'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
                  <Key size={18} color="#ef4444" />
                  <h4 style={{ fontSize: '0.95rem', fontWeight: 700, margin: 0, color: '#f87171' }}>
                    Brute Force / Credential Breach Detected
                  </h4>
                </div>
                {bruteEvents.map((bf, i) => (
                  <div key={i} style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '0.8rem' }}>
                    <div style={{ backgroundColor: 'rgba(0,0,0,0.3)', padding: '10px 14px', borderRadius: '8px' }}>
                      <div>Failed Attempts: <strong>{bf.failed_count}</strong></div>
                      <div>Duration: <strong>{bf.duration_seconds}s</strong></div>
                      <div>Attacker IPs: <strong>{bf.attacker_ips.join(', ')}</strong></div>
                      <div>Status: <span className="badge badge-critical" style={{ fontSize: '0.62rem' }}>{bf.final_status}</span></div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="card" style={{ padding: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                  <ShieldCheck size={20} color="#10b981" />
                  <h4 style={{ fontSize: '0.95rem', fontWeight: 700, margin: 0, color: '#34d399' }}>
                    Velocity & Geolocation Verification
                  </h4>
                </div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  No geographic jumps or physical velocity anomalies detected. Sequential authentications remained within regular travel thresholds.
                </p>
                <div style={{ marginTop: '10px', fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                  Isolation Forest ML Anomaly Probability: <strong>{(result?.metadata?.ml_anomaly_score * 100 || 0).toFixed(1)}%</strong>
                </div>
              </div>
            )}
          </div>

          {/* SOC Human Explanation Card */}
          <div className="card" style={{ padding: '20px', borderLeft: `4px solid ${riskColor(result.risk_level)}` }}>
            <h4 style={{ fontSize: '0.9rem', fontWeight: 700, margin: '0 0 8px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Terminal size={16} color={riskColor(result.risk_level)} />
              SOC Analyst Natural Language Explanation
            </h4>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-primary)', lineHeight: 1.6, margin: 0 }}>
              {result.human_explanation}
            </p>
          </div>

          {/* MITRE ATT&CK & Indicators Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
            {/* MITRE ATT&CK Techniques */}
            <div className="card" style={{ padding: '18px' }}>
              <h4 style={{ fontSize: '0.85rem', fontWeight: 700, margin: '0 0 12px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Layers size={16} color="var(--accent-cyan)" />
                MITRE ATT&CK Matrix Mapping
              </h4>
              {result.mitre_attack_techniques.length > 0 ? (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                  {result.mitre_attack_techniques.map((tech, idx) => (
                    <span
                      key={idx}
                      style={{
                        backgroundColor: 'rgba(14, 165, 233, 0.12)',
                        border: '1px solid rgba(14, 165, 233, 0.3)',
                        borderRadius: '6px',
                        padding: '5px 10px',
                        fontSize: '0.74rem',
                        fontWeight: 600,
                        color: 'var(--accent-cyan)'
                      }}
                    >
                      {tech}
                    </span>
                  ))}
                </div>
              ) : (
                <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  No adversarial MITRE ATT&CK techniques mapped for this event.
                </span>
              )}
            </div>

            {/* Recommended Response Actions */}
            <div className="card" style={{ padding: '18px' }}>
              <h4 style={{ fontSize: '0.85rem', fontWeight: 700, margin: '0 0 12px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Shield size={16} color="#34d399" />
                Recommended Response Playbook
              </h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {result.recommended_actions.map((action, idx) => (
                  <div
                    key={idx}
                    style={{
                      backgroundColor: 'rgba(15, 23, 42, 0.6)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '6px',
                      padding: '8px 12px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center'
                    }}
                  >
                    <div>
                      <div style={{ fontSize: '0.8rem', fontWeight: 600 }}>{action.title}</div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>{action.description}</div>
                    </div>
                    <span className="badge badge-low" style={{ fontSize: '0.62rem' }}>
                      P{action.priority}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
