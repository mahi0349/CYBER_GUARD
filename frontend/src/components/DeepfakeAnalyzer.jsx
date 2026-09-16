import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Eye,
  Upload,
  Image as ImageIcon,
  UserX,
  Shield,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Zap,
  FileWarning,
  Loader2,
  ChevronDown,
  ChevronUp,
  Target,
  Activity,
  Scan,
  Info,
  Crosshair,
} from 'lucide-react';
import { analyzeDeepfakeImage, analyzeImpersonation, fetchDeepfakeSamples } from '../api/client';

// ── Badge helpers ────────────────────────────────────────────────────────

const riskBadgeClass = (level) => {
  const map = { Safe: 'badge-safe', Low: 'badge-low', Medium: 'badge-medium', High: 'badge-high', Critical: 'badge-critical' };
  return `badge ${map[level] || 'badge-low'}`;
};

const riskColor = (level) => {
  const map = { Safe: '#10b981', Low: '#38bdf8', Medium: '#f59e0b', High: '#f87171', Critical: '#ef4444' };
  return map[level] || '#94a3b8';
};

// ── Risk Gauge SVG ──────────────────────────────────────────────────────

function RiskGauge({ score, level }) {
  const pct = Math.min(100, Math.max(0, score));
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (pct / 100) * circumference;

  return (
    <div style={{ textAlign: 'center', padding: '16px 0' }}>
      <svg width="180" height="110" viewBox="0 0 180 110">
        <path d="M 10 100 A 70 70 0 0 1 170 100" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="12" strokeLinecap="round" />
        <path d="M 10 100 A 70 70 0 0 1 170 100" fill="none" stroke={riskColor(level)} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={`${circumference / 2}`} strokeDashoffset={dashOffset / 2}
          style={{ transition: 'stroke-dashoffset 1.2s ease-out, stroke 0.6s ease' }} />
        <text x="90" y="80" textAnchor="middle" fill="#ffffff" fontSize="28" fontWeight="800">{score.toFixed(1)}</text>
        <text x="90" y="98" textAnchor="middle" fill={riskColor(level)} fontSize="13" fontWeight="700">{level}</text>
      </svg>
    </div>
  );
}

// ── Main Component ──────────────────────────────────────────────────────

export default function DeepfakeAnalyzer({ onAnalysisComplete }) {
  const [activeMode, setActiveMode] = useState('image'); // 'image' | 'impersonation'
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [samples, setSamples] = useState(null);
  const [expandedSections, setExpandedSections] = useState({});

  // Image mode state
  const [selectedFile, setSelectedFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef(null);

  // Impersonation mode state
  const [impForm, setImpForm] = useState({
    text_content: '',
    claimed_identity: '',
    claimed_organization: '',
    channel: 'Email',
    urgency_context: '',
  });

  // Load samples on mount
  useEffect(() => {
    fetchDeepfakeSamples()
      .then(setSamples)
      .catch(() => {});
  }, []);

  const toggleSection = (key) => {
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  // ── Image Upload Handlers ──────────────────────────────────────────

  const handleFileSelect = useCallback((file) => {
    if (!file) return;
    const validTypes = ['image/jpeg', 'image/png', 'image/jpg', 'image/webp'];
    if (!validTypes.includes(file.type)) {
      setError('Please upload a JPEG, PNG, or WebP image.');
      return;
    }
    if (file.size > 10 * 1024 * 1024) {
      setError('File size exceeds 10MB limit.');
      return;
    }
    setSelectedFile(file);
    setPreviewUrl(URL.createObjectURL(file));
    setError(null);
    setResult(null);
  }, []);

  const handleDragOver = (e) => { e.preventDefault(); setIsDragging(true); };
  const handleDragLeave = (e) => { e.preventDefault(); setIsDragging(false); };
  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFileSelect(file);
  };

  // ── Analysis Handlers ─────────────────────────────────────────────

  const runImageAnalysis = async () => {
    if (!selectedFile) { setError('Please select an image first.'); return; }
    setLoading(true);
    setError(null);
    try {
      const data = await analyzeDeepfakeImage(selectedFile);
      setResult(data);
      onAnalysisComplete?.(data);
      setExpandedSections({ indicators: true, explanation: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const runImpersonationAnalysis = async () => {
    if (!impForm.text_content && !impForm.claimed_identity && !impForm.claimed_organization) {
      setError('Provide at least text content, claimed identity, or claimed organization.');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const data = await analyzeImpersonation(impForm);
      setResult(data);
      onAnalysisComplete?.(data);
      setExpandedSections({ indicators: true, explanation: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const loadImpersonationSample = (sample) => {
    setImpForm({
      text_content: sample.text_content || '',
      claimed_identity: sample.claimed_identity || '',
      claimed_organization: sample.claimed_organization || '',
      channel: 'Email',
      urgency_context: sample.urgency_context || '',
    });
    setResult(null);
    setError(null);
  };

  const resetAll = () => {
    setSelectedFile(null);
    setPreviewUrl(null);
    setResult(null);
    setError(null);
    setImpForm({ text_content: '', claimed_identity: '', claimed_organization: '', channel: 'Email', urgency_context: '' });
  };

  // ── Render ─────────────────────────────────────────────────────────

  return (
    <div>
      {/* Module Header */}
      <section style={{ marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '6px' }}>
          <div style={{
            width: '44px', height: '44px', borderRadius: '10px',
            background: 'linear-gradient(135deg, #8b5cf6, #a855f7)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 20px rgba(139, 92, 246, 0.4)'
          }}>
            <Eye size={24} color="#ffffff" />
          </div>
          <div>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: '#ffffff', margin: 0 }}>
              Deepfake & Impersonation Analyzer
            </h1>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', margin: 0 }}>
              Scenario B — Image forensics (ELA + DCT) and authority-figure impersonation detection
            </p>
          </div>
        </div>
      </section>

      {/* Mode Tabs */}
      <div style={{
        display: 'flex', gap: '6px', padding: '4px', borderRadius: '10px',
        backgroundColor: 'rgba(15, 23, 42, 0.8)', border: '1px solid var(--border-subtle)',
        marginBottom: '20px', width: 'fit-content'
      }}>
        <button onClick={() => { setActiveMode('image'); setResult(null); setError(null); }}
          style={{
            display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '8px 16px',
            borderRadius: '7px', border: 'none', fontSize: '0.82rem', fontWeight: 600, cursor: 'pointer',
            backgroundColor: activeMode === 'image' ? 'var(--accent-purple)' : 'transparent',
            color: activeMode === 'image' ? '#ffffff' : 'var(--text-secondary)', transition: 'all 0.2s'
          }}>
          <ImageIcon size={15} /> Image Forensics
        </button>
        <button onClick={() => { setActiveMode('impersonation'); setResult(null); setError(null); }}
          style={{
            display: 'inline-flex', alignItems: 'center', gap: '6px', padding: '8px 16px',
            borderRadius: '7px', border: 'none', fontSize: '0.82rem', fontWeight: 600, cursor: 'pointer',
            backgroundColor: activeMode === 'impersonation' ? 'var(--accent-purple)' : 'transparent',
            color: activeMode === 'impersonation' ? '#ffffff' : 'var(--text-secondary)', transition: 'all 0.2s'
          }}>
          <UserX size={15} /> Impersonation Detection
        </button>
      </div>

      {/* Error Banner */}
      {error && (
        <div style={{
          backgroundColor: 'rgba(239, 68, 68, 0.12)', border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: '10px', padding: '12px 16px', marginBottom: '16px',
          display: 'flex', alignItems: 'center', gap: '10px', fontSize: '0.85rem'
        }}>
          <AlertTriangle color="#ef4444" size={18} />
          <span style={{ color: '#fca5a5' }}>{error}</span>
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: result ? '1fr 1fr' : '1fr', gap: '20px' }}>
        {/* ── Left Panel: Input ──────────────────────────────────────── */}
        <div>
          {activeMode === 'image' ? (
            /* Image Upload Mode */
            <div className="cyber-card" style={{ padding: '24px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
                <Scan size={18} color="#8b5cf6" />
                <h2 style={{ fontSize: '1rem', fontWeight: 700, margin: 0 }}>Image Forensics Analysis</h2>
              </div>

              {/* Drag & Drop Zone */}
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                style={{
                  border: `2px dashed ${isDragging ? '#8b5cf6' : 'var(--border-subtle)'}`,
                  borderRadius: '12px',
                  padding: previewUrl ? '12px' : '40px 20px',
                  textAlign: 'center',
                  cursor: 'pointer',
                  backgroundColor: isDragging ? 'rgba(139, 92, 246, 0.08)' : 'rgba(255,255,255,0.02)',
                  transition: 'all 0.2s',
                  marginBottom: '16px'
                }}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/jpeg,image/png,image/webp"
                  style={{ display: 'none' }}
                  onChange={(e) => handleFileSelect(e.target.files?.[0])}
                />
                {previewUrl ? (
                  <div>
                    <img src={previewUrl} alt="Preview"
                      style={{ maxWidth: '100%', maxHeight: '250px', borderRadius: '8px', marginBottom: '8px' }} />
                    <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                      {selectedFile?.name} ({(selectedFile?.size / 1024).toFixed(1)} KB) — Click to change
                    </p>
                  </div>
                ) : (
                  <div>
                    <Upload size={36} color="var(--text-muted)" style={{ marginBottom: '10px' }} />
                    <p style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                      Drag & Drop Image or Click to Browse
                    </p>
                    <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      Supports JPEG, PNG, WebP — Max 10MB
                    </p>
                  </div>
                )}
              </div>

              {/* Analysis Tips */}
              <div style={{
                padding: '12px 16px', borderRadius: '8px',
                backgroundColor: 'rgba(139, 92, 246, 0.06)', border: '1px solid rgba(139, 92, 246, 0.15)',
                marginBottom: '16px'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '6px' }}>
                  <Info size={14} color="#a78bfa" />
                  <span style={{ fontSize: '0.75rem', fontWeight: 600, color: '#a78bfa' }}>Analysis Tips</span>
                </div>
                <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: '1.6' }}>
                  <li>Try uploading a photo edited with filters or retouching tools</li>
                  <li>Screenshots and re-saved images show double-compression artifacts</li>
                  <li>Compare an original photo vs its edited version to see ELA differences</li>
                </ul>
              </div>

              {/* Action Buttons */}
              <div style={{ display: 'flex', gap: '10px' }}>
                <button onClick={runImageAnalysis} disabled={!selectedFile || loading}
                  className="btn-cyber-primary"
                  style={{ flex: 1, justifyContent: 'center', padding: '10px', fontSize: '0.85rem', opacity: (!selectedFile || loading) ? 0.5 : 1 }}>
                  {loading ? <Loader2 size={16} className="animate-spin" /> : <Scan size={16} />}
                  {loading ? 'Analyzing Image...' : 'Run Forensic Analysis'}
                </button>
                <button onClick={resetAll} className="btn-cyber-secondary" style={{ padding: '10px 16px', fontSize: '0.82rem' }}>
                  Reset
                </button>
              </div>
            </div>
          ) : (
            /* Impersonation Detection Mode */
            <div className="cyber-card" style={{ padding: '24px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
                <UserX size={18} color="#8b5cf6" />
                <h2 style={{ fontSize: '1rem', fontWeight: 700, margin: 0 }}>Impersonation Detection</h2>
              </div>

              {/* Form Fields */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', marginBottom: '16px' }}>
                <div>
                  <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px', display: 'block' }}>
                    Message Content *
                  </label>
                  <textarea
                    value={impForm.text_content}
                    onChange={(e) => setImpForm(prev => ({ ...prev, text_content: e.target.value }))}
                    placeholder="Paste the suspicious message content here..."
                    rows={6}
                    style={{
                      width: '100%', padding: '10px 14px', borderRadius: '8px', fontSize: '0.85rem',
                      backgroundColor: 'rgba(15, 23, 42, 0.6)', border: '1px solid var(--border-subtle)',
                      color: '#ffffff', resize: 'vertical', fontFamily: 'inherit', lineHeight: '1.5',
                      outline: 'none', boxSizing: 'border-box'
                    }}
                  />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                  <div>
                    <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px', display: 'block' }}>
                      Claimed Identity
                    </label>
                    <input type="text" value={impForm.claimed_identity}
                      onChange={(e) => setImpForm(prev => ({ ...prev, claimed_identity: e.target.value }))}
                      placeholder="e.g., James Morrison, CEO"
                      style={{
                        width: '100%', padding: '9px 14px', borderRadius: '8px', fontSize: '0.85rem',
                        backgroundColor: 'rgba(15, 23, 42, 0.6)', border: '1px solid var(--border-subtle)',
                        color: '#ffffff', outline: 'none', boxSizing: 'border-box'
                      }}
                    />
                  </div>
                  <div>
                    <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px', display: 'block' }}>
                      Claimed Organization
                    </label>
                    <input type="text" value={impForm.claimed_organization}
                      onChange={(e) => setImpForm(prev => ({ ...prev, claimed_organization: e.target.value }))}
                      placeholder="e.g., Microsoft, HDFC Bank"
                      style={{
                        width: '100%', padding: '9px 14px', borderRadius: '8px', fontSize: '0.85rem',
                        backgroundColor: 'rgba(15, 23, 42, 0.6)', border: '1px solid var(--border-subtle)',
                        color: '#ffffff', outline: 'none', boxSizing: 'border-box'
                      }}
                    />
                  </div>
                </div>

                <div>
                  <label style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '4px', display: 'block' }}>
                    Urgency Context
                  </label>
                  <input type="text" value={impForm.urgency_context}
                    onChange={(e) => setImpForm(prev => ({ ...prev, urgency_context: e.target.value }))}
                    placeholder="e.g., Immediate wire transfer before end of business"
                    style={{
                      width: '100%', padding: '9px 14px', borderRadius: '8px', fontSize: '0.85rem',
                      backgroundColor: 'rgba(15, 23, 42, 0.6)', border: '1px solid var(--border-subtle)',
                      color: '#ffffff', outline: 'none', boxSizing: 'border-box'
                    }}
                  />
                </div>
              </div>

              {/* One-Click Samples */}
              {samples?.impersonation_samples && (
                <div style={{ marginBottom: '16px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '8px', cursor: 'pointer' }}
                    onClick={() => toggleSection('samples')}>
                    <Target size={14} color="#a78bfa" />
                    <span style={{ fontSize: '0.78rem', fontWeight: 600, color: '#a78bfa' }}>One-Click Test Samples</span>
                    {expandedSections.samples ? <ChevronUp size={14} color="#a78bfa" /> : <ChevronDown size={14} color="#a78bfa" />}
                  </div>
                  {expandedSections.samples && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '220px', overflowY: 'auto' }}>
                      {samples.impersonation_samples.map((s) => (
                        <button key={s.id} onClick={() => loadImpersonationSample(s)}
                          style={{
                            display: 'flex', flexDirection: 'column', alignItems: 'flex-start',
                            padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--border-subtle)',
                            backgroundColor: 'rgba(255,255,255,0.02)', cursor: 'pointer',
                            textAlign: 'left', transition: 'all 0.15s', width: '100%',
                            color: 'inherit'
                          }}
                          onMouseOver={(e) => e.currentTarget.style.backgroundColor = 'rgba(139, 92, 246, 0.08)'}
                          onMouseOut={(e) => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.02)'}
                        >
                          <span style={{ fontSize: '0.82rem', fontWeight: 600 }}>{s.title}</span>
                          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '2px' }}>{s.description}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Action Buttons */}
              <div style={{ display: 'flex', gap: '10px' }}>
                <button onClick={runImpersonationAnalysis} disabled={loading}
                  className="btn-cyber-primary"
                  style={{ flex: 1, justifyContent: 'center', padding: '10px', fontSize: '0.85rem', opacity: loading ? 0.5 : 1 }}>
                  {loading ? <Loader2 size={16} className="animate-spin" /> : <Crosshair size={16} />}
                  {loading ? 'Analyzing...' : 'Detect Impersonation'}
                </button>
                <button onClick={resetAll} className="btn-cyber-secondary" style={{ padding: '10px 16px', fontSize: '0.82rem' }}>
                  Reset
                </button>
              </div>
            </div>
          )}
        </div>

        {/* ── Right Panel: Results ────────────────────────────────────── */}
        {result && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {/* Risk Score Gauge */}
            <div className="cyber-card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '8px' }}>
                <Shield size={18} color={riskColor(result.risk_level)} />
                <h3 style={{ fontSize: '1rem', fontWeight: 700, margin: 0 }}>Threat Assessment</h3>
                <span className={riskBadgeClass(result.risk_level)} style={{ marginLeft: 'auto' }}>
                  {result.risk_level}
                </span>
              </div>
              <RiskGauge score={result.risk_score} level={result.risk_level} />
              <div style={{
                textAlign: 'center', padding: '8px 16px', borderRadius: '8px',
                backgroundColor: 'rgba(255,255,255,0.03)', fontSize: '0.82rem', fontWeight: 600,
                color: riskColor(result.risk_level)
              }}>
                {result.threat_classification}
              </div>
            </div>

            {/* Human Explanation */}
            <div className="cyber-card" style={{ padding: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px', cursor: 'pointer' }}
                onClick={() => toggleSection('explanation')}>
                <Activity size={16} color="#a78bfa" />
                <span style={{ fontSize: '0.88rem', fontWeight: 700 }}>AI Threat Rationale</span>
                {expandedSections.explanation ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
              </div>
              {expandedSections.explanation && (
                <p style={{
                  fontSize: '0.84rem', lineHeight: '1.65', color: 'var(--text-secondary)',
                  padding: '12px 16px', borderRadius: '8px', backgroundColor: 'rgba(139, 92, 246, 0.05)',
                  border: '1px solid rgba(139, 92, 246, 0.12)', margin: 0
                }}>
                  {result.human_explanation}
                </p>
              )}
            </div>

            {/* Image Forensics Visualizations */}
            {result.metadata?.analysis_type === 'image_forensics' && (
              <div className="cyber-card" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px', cursor: 'pointer' }}
                  onClick={() => toggleSection('forensics')}>
                  <Scan size={16} color="#8b5cf6" />
                  <span style={{ fontSize: '0.88rem', fontWeight: 700 }}>Forensic Visualizations</span>
                  {expandedSections.forensics ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                </div>
                {(expandedSections.forensics !== false) && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                    {/* ELA Heatmap */}
                    <div style={{
                      padding: '12px', borderRadius: '8px', backgroundColor: 'rgba(255,255,255,0.02)',
                      border: '1px solid var(--border-subtle)'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                        <span style={{ fontSize: '0.78rem', fontWeight: 600, color: '#a78bfa' }}>ELA Heatmap</span>
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                          Score: {(result.metadata.ela_score * 100).toFixed(1)}%
                        </span>
                      </div>
                      {result.metadata.ela_heatmap_base64 && (
                        <img src={`data:image/png;base64,${result.metadata.ela_heatmap_base64}`}
                          alt="ELA Heatmap" style={{ width: '100%', borderRadius: '6px' }} />
                      )}
                      <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '6px', lineHeight: '1.4' }}>
                        Brighter regions indicate compression inconsistencies — potential edits.
                      </p>
                    </div>

                    {/* DCT Spectrum */}
                    <div style={{
                      padding: '12px', borderRadius: '8px', backgroundColor: 'rgba(255,255,255,0.02)',
                      border: '1px solid var(--border-subtle)'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                        <span style={{ fontSize: '0.78rem', fontWeight: 600, color: '#8b5cf6' }}>DCT Frequency Spectrum</span>
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                          Score: {(result.metadata.dct_score * 100).toFixed(1)}%
                        </span>
                      </div>
                      {result.metadata.dct_spectrum_base64 && (
                        <img src={`data:image/png;base64,${result.metadata.dct_spectrum_base64}`}
                          alt="DCT Spectrum" style={{ width: '100%', borderRadius: '6px' }} />
                      )}
                      <p style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '6px', lineHeight: '1.4' }}>
                        Spectral analysis reveals frequency-domain artifacts from re-compression.
                      </p>
                    </div>
                  </div>
                )}

                {/* Forensic Details */}
                {result.metadata.ela_details && (
                  <div style={{
                    marginTop: '12px', padding: '12px', borderRadius: '8px',
                    backgroundColor: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)'
                  }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Forensic Metrics</span>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px', marginTop: '8px' }}>
                      {[
                        { label: 'ELA Mean Error', val: result.metadata.ela_details.global_mean_error?.toFixed(3) },
                        { label: 'ELA Std Dev', val: result.metadata.ela_details.global_std_error?.toFixed(3) },
                        { label: 'Hotspot Regions', val: result.metadata.ela_details.hotspot_count },
                        { label: 'DCT Periodicity', val: result.metadata.dct_details?.periodicity_score?.toFixed(4) },
                        { label: 'HF Mean', val: result.metadata.dct_details?.high_freq_mean?.toFixed(4) },
                        { label: 'Blocks Analyzed', val: result.metadata.dct_details?.blocks_analyzed },
                      ].map((m, i) => (
                        <div key={i} style={{ padding: '6px 8px', borderRadius: '6px', backgroundColor: 'rgba(255,255,255,0.02)' }}>
                          <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', display: 'block' }}>{m.label}</span>
                          <span style={{ fontSize: '0.8rem', fontWeight: 600, color: '#e2e8f0' }}>{m.val ?? 'N/A'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Threat Indicators */}
            {result.indicators?.length > 0 && (
              <div className="cyber-card" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px', cursor: 'pointer' }}
                  onClick={() => toggleSection('indicators')}>
                  <AlertTriangle size={16} color="#f59e0b" />
                  <span style={{ fontSize: '0.88rem', fontWeight: 700 }}>
                    Threat Indicators ({result.indicators.length})
                  </span>
                  {expandedSections.indicators ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                </div>
                {expandedSections.indicators && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {result.indicators.map((ind, idx) => (
                      <div key={idx} style={{
                        padding: '12px 14px', borderRadius: '8px',
                        backgroundColor: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)'
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#f1f5f9' }}>{ind.name}</span>
                          <span style={{
                            fontSize: '0.7rem', fontWeight: 700, padding: '2px 8px', borderRadius: '4px',
                            backgroundColor: ind.weight > 0.6 ? 'rgba(239, 68, 68, 0.15)' : ind.weight > 0.3 ? 'rgba(245, 158, 11, 0.15)' : 'rgba(56, 189, 248, 0.15)',
                            color: ind.weight > 0.6 ? '#f87171' : ind.weight > 0.3 ? '#fbbf24' : '#38bdf8',
                          }}>
                            Weight: {ind.weight}
                          </span>
                        </div>
                        <div style={{ fontSize: '0.72rem', color: '#a78bfa', marginBottom: '4px' }}>
                          {ind.category} — {ind.value}
                        </div>
                        <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', margin: 0, lineHeight: '1.5' }}>
                          {ind.description}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* MITRE ATT&CK Techniques */}
            {result.mitre_attack_techniques?.length > 0 && (
              <div className="cyber-card" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
                  <Crosshair size={16} color="#ef4444" />
                  <span style={{ fontSize: '0.88rem', fontWeight: 700 }}>MITRE ATT&CK Mapping</span>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                  {result.mitre_attack_techniques.map((t, i) => (
                    <span key={i} style={{
                      display: 'inline-flex', padding: '5px 10px', borderRadius: '6px', fontSize: '0.75rem',
                      fontWeight: 600, backgroundColor: 'rgba(239, 68, 68, 0.1)', color: '#fca5a5',
                      border: '1px solid rgba(239, 68, 68, 0.2)', fontFamily: 'var(--font-mono)'
                    }}>
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Recommended Actions */}
            {result.recommended_actions?.length > 0 && (
              <div className="cyber-card" style={{ padding: '20px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px', cursor: 'pointer' }}
                  onClick={() => toggleSection('actions')}>
                  <Zap size={16} color="#10b981" />
                  <span style={{ fontSize: '0.88rem', fontWeight: 700 }}>
                    Recommended Actions ({result.recommended_actions.length})
                  </span>
                  {expandedSections.actions ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                </div>
                {(expandedSections.actions !== false) && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {result.recommended_actions.map((action, idx) => (
                      <div key={idx} style={{
                        padding: '12px 14px', borderRadius: '8px',
                        backgroundColor: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)',
                        display: 'flex', alignItems: 'flex-start', gap: '12px'
                      }}>
                        <div style={{
                          width: '28px', height: '28px', borderRadius: '6px', flexShrink: 0,
                          backgroundColor: action.executed ? 'rgba(16, 185, 129, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                          display: 'flex', alignItems: 'center', justifyContent: 'center', marginTop: '2px'
                        }}>
                          {action.executed ? <CheckCircle2 size={14} color="#10b981" /> : <FileWarning size={14} color="#f59e0b" />}
                        </div>
                        <div style={{ flex: 1 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                            <span style={{ fontSize: '0.82rem', fontWeight: 700, color: '#f1f5f9' }}>{action.title}</span>
                            <span style={{
                              fontSize: '0.65rem', fontWeight: 600, padding: '2px 6px', borderRadius: '4px',
                              backgroundColor: action.executed ? 'rgba(16, 185, 129, 0.12)' : 'rgba(245, 158, 11, 0.12)',
                              color: action.executed ? '#34d399' : '#fbbf24'
                            }}>
                              {action.executed ? 'EXECUTED' : 'PENDING'}
                            </span>
                          </div>
                          <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', margin: 0, lineHeight: '1.4' }}>
                            {action.description}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
