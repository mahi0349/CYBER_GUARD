import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Activity, 
  CheckCircle2, 
  AlertTriangle, 
  Terminal, 
  Server, 
  Cpu, 
  Database,
  RefreshCw,
  ExternalLink,
  Layers,
  Lock,
  Eye,
  Mail,
  Zap,
  Radio,
  FileCode,
  LayoutDashboard,
  UserX
} from 'lucide-react';
import { fetchHealth, fetchEvents } from './api/client';
import PhishingAnalyzer from './components/PhishingAnalyzer';
import DeepfakeAnalyzer from './components/DeepfakeAnalyzer';
import AccountAnalyzer from './components/AccountAnalyzer';

function App() {
  const [activeTab, setActiveTab] = useState('phishing'); // 'overview' | 'phishing' | 'deepfake' | 'account'
  const [healthData, setHealthData] = useState(null);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastCheckTime, setLastCheckTime] = useState(null);
  const [latestAnalysis, setLatestAnalysis] = useState(null);

  const checkConnection = async () => {
    setLoading(true);
    setError(null);
    try {
      const [health, eventList] = await Promise.all([
        fetchHealth(),
        fetchEvents(15).catch(() => [])
      ]);
      setHealthData(health);
      setEvents(eventList);
      setLastCheckTime(new Date().toLocaleTimeString());
    } catch (err) {
      console.error('Connection error:', err);
      setError(err.message || 'Failed to connect to CYBERGUARD Backend API');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkConnection();
  }, []);

  const handleAnalysisComplete = (newResult) => {
    setLatestAnalysis(newResult);
    // Refresh event store
    fetchEvents(15)
      .then(data => setEvents(data))
      .catch(() => {});
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Top Cyber Navigation Bar */}
      <header style={{
        backgroundColor: 'rgba(8, 12, 20, 0.9)',
        backdropFilter: 'blur(16px)',
        borderBottom: '1px solid var(--border-subtle)',
        position: 'sticky',
        top: 0,
        zIndex: 50,
        padding: '12px 28px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '12px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '40px',
            height: '40px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, #06b6d4, #3b82f6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 16px rgba(6, 182, 212, 0.4)'
          }}>
            <Shield size={22} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '1.25rem', fontWeight: 800, letterSpacing: '0.04em', background: 'linear-gradient(to right, #ffffff, #94a3b8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                CYBERGUARD
              </span>
              <span className="badge badge-safe" style={{ fontSize: '0.62rem' }}>
                AI DEFENCE CORE
              </span>
            </div>
            <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              Odisha Knowledge Corporation Limited (OKCL) Cyber Defence Platform
            </p>
          </div>
        </div>

        {/* Center Tab Navigation */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          padding: '4px',
          borderRadius: '10px',
          backgroundColor: 'rgba(15, 23, 42, 0.8)',
          border: '1px solid var(--border-subtle)'
        }}>
          <button
            onClick={() => setActiveTab('phishing')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '7px 14px',
              borderRadius: '6px',
              border: 'none',
              fontSize: '0.8rem',
              fontWeight: 600,
              cursor: 'pointer',
              backgroundColor: activeTab === 'phishing' ? 'var(--accent-cyan)' : 'transparent',
              color: activeTab === 'phishing' ? '#ffffff' : 'var(--text-secondary)',
              transition: 'all 0.2s'
            }}
          >
            <Mail size={14} />
            Scenario A: Phishing Detector
          </button>

          <button
            onClick={() => setActiveTab('deepfake')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '7px 14px',
              borderRadius: '6px',
              border: 'none',
              fontSize: '0.8rem',
              fontWeight: 600,
              cursor: 'pointer',
              backgroundColor: activeTab === 'deepfake' ? 'var(--accent-cyan)' : 'transparent',
              color: activeTab === 'deepfake' ? '#ffffff' : 'var(--text-secondary)',
              transition: 'all 0.2s'
            }}
          >
            <Eye size={14} />
            Scenario B: Deepfake & Impersonation
          </button>

          <button
            onClick={() => setActiveTab('account')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '7px 14px',
              borderRadius: '6px',
              border: 'none',
              fontSize: '0.8rem',
              fontWeight: 600,
              cursor: 'pointer',
              backgroundColor: activeTab === 'account' ? 'var(--accent-cyan)' : 'transparent',
              color: activeTab === 'account' ? '#ffffff' : 'var(--text-secondary)',
              transition: 'all 0.2s'
            }}
          >
            <UserX size={14} />
            Scenario C: Account Takeover
          </button>

          <button
            onClick={() => setActiveTab('overview')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '7px 14px',
              borderRadius: '6px',
              border: 'none',
              fontSize: '0.8rem',
              fontWeight: 600,
              cursor: 'pointer',
              backgroundColor: activeTab === 'overview' ? 'var(--accent-cyan)' : 'transparent',
              color: activeTab === 'overview' ? '#ffffff' : 'var(--text-secondary)',
              transition: 'all 0.2s'
            }}
          >
            <LayoutDashboard size={14} />
            System Architecture & Core
          </button>
        </div>

        {/* Right Status & Diagnostic */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '6px 12px',
            borderRadius: '9999px',
            backgroundColor: 'rgba(15, 23, 42, 0.6)',
            border: '1px solid var(--border-subtle)'
          }}>
            <div className={`pulse-dot ${healthData?.status === 'ONLINE' ? 'online' : ''}`} 
                 style={{ backgroundColor: healthData?.status === 'ONLINE' ? '#10b981' : '#ef4444' }} />
            <span style={{ fontSize: '0.78rem', fontWeight: 600, color: healthData?.status === 'ONLINE' ? '#34d399' : '#f87171' }}>
              {loading ? 'CHECKING...' : healthData?.status === 'ONLINE' ? 'API LIVE :8000' : 'OFFLINE'}
            </span>
          </div>

          <button 
            onClick={checkConnection}
            disabled={loading}
            className="btn-cyber-primary"
            style={{ padding: '7px 12px', fontSize: '0.78rem' }}
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            Diagnostic
          </button>
        </div>
      </header>

      {/* Main Content Viewport */}
      <main style={{ flex: 1, padding: '28px', maxWidth: '1440px', margin: '0 auto', width: '100%' }}>
        {/* Banner Alert if error */}
        {error && (
          <div style={{
            backgroundColor: 'rgba(239, 68, 68, 0.12)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            borderRadius: '10px',
            padding: '16px 20px',
            marginBottom: '24px',
            display: 'flex',
            alignItems: 'center',
            gap: '12px'
          }}>
            <AlertTriangle color="#ef4444" size={20} />
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600, color: '#fca5a5', fontSize: '0.9rem' }}>FastAPI Backend Offline</div>
              <div style={{ fontSize: '0.8rem', color: '#f87171' }}>{error}. Ensure uvicorn is running on port 8000.</div>
            </div>
            <button onClick={checkConnection} className="btn-cyber-secondary" style={{ fontSize: '0.75rem', padding: '6px 12px' }}>
              Retry
            </button>
          </div>
        )}

        {/* Tab 1: Phishing Analyzer (Scenario A) */}
        {activeTab === 'phishing' && (
          <PhishingAnalyzer onAnalysisComplete={handleAnalysisComplete} />
        )}

        {/* Tab 2: Deepfake & Impersonation Analyzer (Scenario B) */}
        {activeTab === 'deepfake' && (
          <DeepfakeAnalyzer onAnalysisComplete={handleAnalysisComplete} />
        )}

        {/* Tab 3: Account Takeover & Anomaly Analyzer (Scenario C) */}
        {activeTab === 'account' && (
          <AccountAnalyzer onAnalysisComplete={handleAnalysisComplete} />
        )}

        {/* Tab 4: System Architecture & Core Diagnostics */}
        {activeTab === 'overview' && (
          <div>
            <section style={{ marginBottom: '28px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                <div>
                  <h1 style={{ fontSize: '1.75rem', fontWeight: 800, marginBottom: '6px', color: '#ffffff' }}>
                    CYBERGUARD Architecture & Readiness Matrix
                  </h1>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>
                    Multi-source cyber threat intelligence engine with explainable AI reasoning and autonomous response recommendations.
                  </p>
                </div>
                {lastCheckTime && (
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Last ping: {lastCheckTime}
                  </span>
                )}
              </div>
            </section>

            {/* 4 Feature Architecture Cards */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              gap: '20px',
              marginBottom: '32px'
            }}>
              {/* Card 1: Scenario A */}
              <div className="cyber-card" style={{ padding: '24px', borderColor: 'var(--border-active)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
                  <div style={{
                    width: '38px',
                    height: '38px',
                    borderRadius: '8px',
                    backgroundColor: 'rgba(6, 182, 212, 0.15)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <Lock size={20} color="#06b6d4" />
                  </div>
                  <span className="badge badge-safe">Scenario A : READY</span>
                </div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '8px' }}>Phishing & Social Engineering</h3>
                <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: '1.5', marginBottom: '16px' }}>
                  NLP feature extraction + Levenshtein typo-squatting domain forensics + TF-IDF ML attribution.
                </p>
                <button 
                  onClick={() => setActiveTab('phishing')}
                  className="btn-cyber-primary" 
                  style={{ width: '100%', justifyContent: 'center', fontSize: '0.75rem', padding: '8px' }}
                >
                  Open Phishing Analyzer
                </button>
              </div>

              {/* Card 2: Scenario B */}
              <div className="cyber-card" style={{ padding: '24px', borderColor: 'var(--border-active)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
                  <div style={{
                    width: '38px',
                    height: '38px',
                    borderRadius: '8px',
                    backgroundColor: 'rgba(139, 92, 246, 0.15)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <Eye size={20} color="#8b5cf6" />
                  </div>
                  <span className="badge badge-safe">Scenario B : READY</span>
                </div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '8px' }}>Deepfake & Impersonation</h3>
                <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: '1.5', marginBottom: '16px' }}>
                  Error Level Analysis (ELA) + DCT frequency forensics + authority figure impersonation heuristics.
                </p>
                <button 
                  onClick={() => setActiveTab('deepfake')}
                  className="btn-cyber-primary" 
                  style={{ width: '100%', justifyContent: 'center', fontSize: '0.75rem', padding: '8px' }}
                >
                  Open Deepfake & Impersonation Analyzer
                </button>
              </div>

              {/* Card 3: Scenario C */}
              <div className="cyber-card" style={{ padding: '24px', borderColor: 'var(--border-active)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
                  <div style={{
                    width: '38px',
                    height: '38px',
                    borderRadius: '8px',
                    backgroundColor: 'rgba(245, 158, 11, 0.15)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <UserX size={20} color="#f59e0b" />
                  </div>
                  <span className="badge badge-safe">Scenario C : READY</span>
                </div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '8px' }}>Account Takeover & Anomaly</h3>
                <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: '1.5', marginBottom: '16px' }}>
                  Physical geo-velocity validation (Haversine) + brute-force bursts + device novelty & Isolation Forest ML.
                </p>
                <button 
                  onClick={() => setActiveTab('account')}
                  className="btn-cyber-primary" 
                  style={{ width: '100%', justifyContent: 'center', fontSize: '0.75rem', padding: '8px' }}
                >
                  Open Account Anomaly Analyzer
                </button>
              </div>

              {/* Card 4: Unified Risk & Response Engine */}
              <div className="cyber-card" style={{ padding: '24px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
                  <div style={{
                    width: '38px',
                    height: '38px',
                    borderRadius: '8px',
                    backgroundColor: 'rgba(16, 185, 129, 0.15)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}>
                    <Layers size={20} color="#10b981" />
                  </div>
                  <span className="badge badge-safe">Unified Core : ACTIVE</span>
                </div>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '8px' }}>Risk Engine & Response</h3>
                <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: '1.5', marginBottom: '16px' }}>
                  Normalized 0-100 scoring + human-readable evidence-driven explanations + automated mitigation recommendations.
                </p>
                <div style={{ fontSize: '0.75rem', color: '#34d399', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <CheckCircle2 size={14} /> Database Store Active
                </div>
              </div>
            </div>

            {/* Live Backend Telemetry & Health Probe */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))', gap: '24px' }}>
              {/* Telemetry Card */}
              <div className="cyber-card" style={{ padding: '24px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
                  <Activity size={18} color="#06b6d4" />
                  <h2 style={{ fontSize: '1.05rem', fontWeight: 700 }}>Backend Microservice Telemetry</h2>
                </div>
                
                {healthData ? (
                  <div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
                      <div style={{ padding: '12px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>SERVICE</span>
                        <p style={{ fontSize: '0.85rem', fontWeight: 600, marginTop: '2px' }}>{healthData.service}</p>
                      </div>
                      <div style={{ padding: '12px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>VERSION</span>
                        <p style={{ fontSize: '0.85rem', fontWeight: 600, marginTop: '2px' }}>v{healthData.version}</p>
                      </div>
                      <div style={{ padding: '12px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>DATABASE</span>
                        <p style={{ fontSize: '0.85rem', fontWeight: 600, marginTop: '2px' }}>SQLite Event Store (Active)</p>
                      </div>
                      <div style={{ padding: '12px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>TOTAL LOGGED EVENTS</span>
                        <p style={{ fontSize: '0.85rem', fontWeight: 600, color: '#38bdf8', marginTop: '2px' }}>{events.length} Incident(s)</p>
                      </div>
                    </div>

                    <div style={{ marginTop: '16px' }}>
                      <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>MODULE READINESS MATRIX</span>
                      <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                        {Object.entries(healthData.modules || {}).map(([key, status]) => (
                          <div key={key} style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            padding: '6px 10px',
                            borderRadius: '6px',
                            backgroundColor: 'rgba(255,255,255,0.02)',
                            fontSize: '0.78rem'
                          }}>
                            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{key}</span>
                            <span className="badge badge-safe">{status}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : (
                  <div style={{ padding: '30px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    Waiting for backend heartbeat...
                  </div>
                )}
              </div>

              {/* SQLite Recent Threat Events Stream */}
              <div className="cyber-card" style={{ padding: '24px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <Database size={18} color="#8b5cf6" />
                    <h2 style={{ fontSize: '1.05rem', fontWeight: 700 }}>Live Incident Event Stream (SQLite)</h2>
                  </div>
                  <span className="badge badge-low">{events.length} Events</span>
                </div>

                <div style={{
                  backgroundColor: '#05070d',
                  borderRadius: '8px',
                  border: '1px solid var(--border-subtle)',
                  padding: '12px',
                  maxHeight: '300px',
                  overflowY: 'auto',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px'
                }}>
                  {events.length > 0 ? (
                    events.map((evt, idx) => (
                      <div key={idx} style={{
                        padding: '10px 12px',
                        borderRadius: '6px',
                        backgroundColor: 'rgba(255,255,255,0.03)',
                        border: '1px solid var(--border-subtle)',
                        fontSize: '0.8rem'
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <span style={{ fontWeight: 700, color: evt.risk_level === 'Safe' ? '#34d399' : '#f87171' }}>
                            {evt.threat_classification}
                          </span>
                          <span className={`badge ${evt.risk_level === 'Safe' ? 'badge-safe' : evt.risk_level === 'Critical' ? 'badge-critical' : 'badge-high'}`}>
                            {evt.risk_level} ({evt.risk_score})
                          </span>
                        </div>
                        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {evt.human_explanation}
                        </p>
                      </div>
                    ))
                  ) : (
                    <div style={{ color: 'var(--text-muted)', padding: '20px', textAlign: 'center', fontSize: '0.8rem' }}>
                      No events logged in database yet. Run analysis in Scenario A to trigger events.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer style={{
        padding: '16px 32px',
        borderTop: '1px solid var(--border-subtle)',
        fontSize: '0.75rem',
        color: 'var(--text-muted)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '10px'
      }}>
        <span>CYBERGUARD — Odisha Knowledge Corporation Limited (OKCL) Hackathon</span>
        <span>Scenario A: Phishing · Scenario B: Deepfake & Impersonation — Active</span>
      </footer>
    </div>
  );
}

export default App;
