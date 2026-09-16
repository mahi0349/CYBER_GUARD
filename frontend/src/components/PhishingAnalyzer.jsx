import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Zap, 
  Link as LinkIcon, 
  Mail, 
  CheckCircle, 
  Clock, 
  FileText, 
  Cpu, 
  ExternalLink,
  Layers,
  ChevronRight,
  BarChart3,
  Flame,
  CornerDownRight
} from 'lucide-react';
import { analyzePhishing, fetchPhishingSamples, fetchPhishingEvaluation } from '../api/client';

export default function PhishingAnalyzer({ onAnalysisComplete }) {
  const [samples, setSamples] = useState([]);
  const [selectedSampleId, setSelectedSampleId] = useState('');
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [text, setText] = useState('');
  const [urls, setUrls] = useState('');
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  
  const [evalData, setEvalData] = useState(null);
  const [showEval, setShowEval] = useState(false);

  useEffect(() => {
    fetchPhishingSamples()
      .then(data => {
        setSamples(data);
        if (data.length > 0) {
          loadSample(data[0]);
        }
      })
      .catch(err => console.error('Failed to load samples:', err));

    fetchPhishingEvaluation()
      .then(data => setEvalData(data))
      .catch(err => console.error('Failed to load evaluation:', err));
  }, []);

  const loadSample = (sample) => {
    setSelectedSampleId(sample.id);
    setSender(sample.sender || '');
    setSubject(sample.subject || '');
    setText(sample.text || '');
    setUrls((sample.urls || []).join('\n'));
    setResult(null);
  };

  const handleSampleChange = (e) => {
    const id = e.target.value;
    const sample = samples.find(s => s.id === id);
    if (sample) {
      loadSample(sample);
    }
  };

  const handleAnalyze = async (e) => {
    if (e) e.preventDefault();
    setLoading(true);
    setError(null);

    const urlList = urls
      .split('\n')
      .map(u => u.trim())
      .filter(u => u.length > 0);

    try {
      const data = await analyzePhishing({
        sender,
        subject,
        text,
        urls: urlList
      });
      setResult(data);
      if (onAnalysisComplete) {
        onAnalysisComplete(data);
      }
    } catch (err) {
      setError(err.message || 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const getRiskBadgeClass = (level) => {
    switch (level?.toLowerCase()) {
      case 'critical': return 'badge-critical';
      case 'high': return 'badge-high';
      case 'medium': return 'badge-medium';
      case 'low': return 'badge-low';
      default: return 'badge-safe';
    }
  };

  const getRiskScoreColor = (score) => {
    if (score >= 85) return '#ef4444';
    if (score >= 65) return '#f97316';
    if (score >= 40) return '#f59e0b';
    if (score >= 20) return '#3b82f6';
    return '#10b981';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Banner & Sample Preset Bar */}
      <div className="cyber-card" style={{ padding: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span className="badge badge-safe">Scenario A Module</span>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800 }}>AI Phishing & Social Engineering Analyzer</h2>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Deep NLP feature extraction + Levenshtein look-alike domain forensics + TF-IDF ML attribution.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <button
              onClick={() => setShowEval(!showEval)}
              className="btn-cyber-secondary"
              style={{ fontSize: '0.8rem', padding: '8px 14px' }}
            >
              <BarChart3 size={15} />
              {showEval ? 'Hide Evaluation Metrics' : 'Model Accuracy Benchmark'}
            </button>
          </div>
        </div>

        {/* Benchmark Evaluation Drawer */}
        {showEval && evalData && (
          <div style={{
            marginTop: '20px',
            padding: '20px',
            backgroundColor: 'rgba(6, 182, 212, 0.04)',
            borderRadius: '10px',
            border: '1px solid rgba(6, 182, 212, 0.2)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                Cross-Validation & Benchmark Evaluation Results
              </h4>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Evaluated on {evalData.total_samples} Ground-Truth Samples ({evalData.phishing_samples} Phishing / {evalData.legitimate_samples} Legitimate)
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '12px', marginBottom: '16px' }}>
              <div style={{ padding: '12px', background: 'rgba(15,23,42,0.8)', borderRadius: '8px', textAlign: 'center', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>ACCURACY</span>
                <p style={{ fontSize: '1.35rem', fontWeight: 800, color: '#34d399', marginTop: '2px' }}>{(evalData.accuracy * 100).toFixed(1)}%</p>
              </div>
              <div style={{ padding: '12px', background: 'rgba(15,23,42,0.8)', borderRadius: '8px', textAlign: 'center', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>PRECISION</span>
                <p style={{ fontSize: '1.35rem', fontWeight: 800, color: '#38bdf8', marginTop: '2px' }}>{(evalData.precision * 100).toFixed(1)}%</p>
              </div>
              <div style={{ padding: '12px', background: 'rgba(15,23,42,0.8)', borderRadius: '8px', textAlign: 'center', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>RECALL</span>
                <p style={{ fontSize: '1.35rem', fontWeight: 800, color: '#818cf8', marginTop: '2px' }}>{(evalData.recall * 100).toFixed(1)}%</p>
              </div>
              <div style={{ padding: '12px', background: 'rgba(15,23,42,0.8)', borderRadius: '8px', textAlign: 'center', border: '1px solid var(--border-subtle)' }}>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>F1-SCORE</span>
                <p style={{ fontSize: '1.35rem', fontWeight: 800, color: '#a78bfa', marginTop: '2px' }}>{(evalData.f1_score * 100).toFixed(1)}%</p>
              </div>
            </div>

            {evalData.confusion_matrix && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                <span style={{ fontWeight: 600 }}>Confusion Matrix:</span>
                <span>True Positives: <strong style={{ color: '#34d399' }}>{evalData.confusion_matrix.true_positive}</strong></span>
                <span>True Negatives: <strong style={{ color: '#34d399' }}>{evalData.confusion_matrix.true_negative}</strong></span>
                <span>False Positives: <strong style={{ color: '#94a3b8' }}>{evalData.confusion_matrix.false_positive}</strong></span>
                <span>False Negatives: <strong style={{ color: '#94a3b8' }}>{evalData.confusion_matrix.false_negative}</strong></span>
              </div>
            )}
          </div>
        )}

        {/* Preset Selector */}
        <div style={{ marginTop: '16px', display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)' }}>ONE-CLICK TEST SAMPLES:</span>
          <select
            value={selectedSampleId}
            onChange={handleSampleChange}
            style={{
              flex: 1,
              minWidth: '280px',
              padding: '8px 12px',
              backgroundColor: 'rgba(15, 23, 42, 0.9)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '6px',
              color: 'var(--text-primary)',
              fontSize: '0.85rem',
              outline: 'none',
              cursor: 'pointer'
            }}
          >
            {samples.map(s => (
              <option key={s.id} value={s.id}>
                {s.label === 1 ? '🔴 [PHISHING]' : '🟢 [LEGITIMATE]'} {s.category}: {s.subject}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Main Grid: Input Form & Live Results */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))', gap: '24px' }}>
        {/* Left Column: Input Form */}
        <div className="cyber-card" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <Mail size={18} color="#06b6d4" />
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>Inspect Email / SMS Message</h3>
          </div>

          <form onSubmit={handleAnalyze} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}>
                SENDER ADDRESS / HEADER
              </label>
              <input
                type="text"
                value={sender}
                onChange={e => setSender(e.target.value)}
                placeholder="e.g. security-alert@micros0ft-verify.com"
                style={{
                  width: '100%',
                  padding: '10px 14px',
                  backgroundColor: 'rgba(255,255,255,0.02)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  fontSize: '0.85rem',
                  fontFamily: 'var(--font-mono)'
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}>
                SUBJECT LINE
              </label>
              <input
                type="text"
                value={subject}
                onChange={e => setSubject(e.target.value)}
                placeholder="e.g. CRITICAL: Account Password Expiring in 2 Hours"
                style={{
                  width: '100%',
                  padding: '10px 14px',
                  backgroundColor: 'rgba(255,255,255,0.02)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  fontSize: '0.85rem'
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}>
                MESSAGE BODY (EMAIL / SMS / CHAT)
              </label>
              <textarea
                rows={7}
                value={text}
                onChange={e => setText(e.target.value)}
                placeholder="Paste email or message text here..."
                style={{
                  width: '100%',
                  padding: '12px 14px',
                  backgroundColor: 'rgba(255,255,255,0.02)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  fontSize: '0.85rem',
                  fontFamily: 'inherit',
                  resize: 'vertical'
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '4px' }}>
                EMBEDDED URLS (ONE PER LINE)
              </label>
              <textarea
                rows={2}
                value={urls}
                onChange={e => setUrls(e.target.value)}
                placeholder="http://login.micros0ft-verify.com/auth/login.php"
                style={{
                  width: '100%',
                  padding: '10px 14px',
                  backgroundColor: 'rgba(255,255,255,0.02)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  color: 'var(--text-primary)',
                  fontSize: '0.85rem',
                  fontFamily: 'var(--font-mono)'
                }}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-cyber-primary"
              style={{ width: '100%', justifyContent: 'center', marginTop: '6px' }}
            >
              <Zap size={16} />
              {loading ? 'Executing AI Threat Analysis Pipeline...' : 'Run Phishing Detection Pipeline'}
            </button>
          </form>
        </div>

        {/* Right Column: Live Detection & Explanation Pipeline Output */}
        <div className="cyber-card" style={{ padding: '24px', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Layers size={18} color="#8b5cf6" />
              <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>Threat Assessment & Rationale</h3>
            </div>
            {result && (
              <span className={`badge ${getRiskBadgeClass(result.risk_level)}`}>
                {result.risk_level}
              </span>
            )}
          </div>

          {result ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px', flex: 1 }}>
              {/* Risk Score & Classification Card */}
              <div style={{
                padding: '16px',
                borderRadius: '10px',
                backgroundColor: 'rgba(255,255,255,0.02)',
                border: '1px solid var(--border-subtle)'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                  <div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600 }}>THREAT CLASSIFICATION</span>
                    <h4 style={{ fontSize: '1.05rem', fontWeight: 700, color: result.risk_level === 'Safe' ? '#34d399' : '#f87171' }}>
                      {result.threat_classification}
                    </h4>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600 }}>RISK SCORE</span>
                    <p style={{ fontSize: '1.5rem', fontWeight: 800, color: getRiskScoreColor(result.risk_score), lineHeight: '1.2' }}>
                      {result.risk_score} <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>/ 100</span>
                    </p>
                  </div>
                </div>

                {/* Progress bar */}
                <div style={{ height: '6px', backgroundColor: 'rgba(255,255,255,0.08)', borderRadius: '3px', overflow: 'hidden' }}>
                  <div style={{
                    height: '100%',
                    width: `${result.risk_score}%`,
                    backgroundColor: getRiskScoreColor(result.risk_score),
                    transition: 'width 0.4s ease'
                  }} />
                </div>
              </div>

              {/* Natural Language Explanation Box */}
              <div style={{
                padding: '16px',
                borderRadius: '10px',
                backgroundColor: result.risk_level === 'Safe' ? 'rgba(16, 185, 129, 0.06)' : 'rgba(239, 68, 68, 0.06)',
                border: `1px solid ${result.risk_level === 'Safe' ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`
              }}>
                <span style={{
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  color: result.risk_level === 'Safe' ? '#34d399' : '#f87171',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  marginBottom: '8px'
                }}>
                  <Cpu size={14} /> EXPLAINABLE THREAT RATIONALE
                </span>
                <p style={{ fontSize: '0.85rem', lineHeight: '1.6', color: 'var(--text-primary)' }}>
                  {result.human_explanation}
                </p>
              </div>

              {/* Evidence & Forensic Indicators */}
              <div>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', display: 'block', marginBottom: '8px' }}>
                  DETECTED FORENSIC INDICATORS ({result.indicators.length})
                </span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '200px', overflowY: 'auto' }}>
                  {result.indicators.map((ind, i) => (
                    <div key={i} style={{
                      padding: '10px 12px',
                      borderRadius: '6px',
                      backgroundColor: 'rgba(255,255,255,0.02)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '4px'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                          {ind.name}
                        </span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                          Weight: {ind.weight}
                        </span>
                      </div>
                      <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                        {ind.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recommended Response Actions */}
              <div>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', display: 'block', marginBottom: '8px' }}>
                  RECOMMENDED MITIGATION ACTIONS ({result.recommended_actions.length})
                </span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {result.recommended_actions.map((act, i) => (
                    <div key={i} style={{
                      padding: '10px 12px',
                      borderRadius: '6px',
                      backgroundColor: act.is_automated ? 'rgba(6, 182, 212, 0.05)' : 'rgba(255, 255, 255, 0.02)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      alignItems: 'flex-start',
                      justifyContent: 'space-between',
                      gap: '10px'
                    }}>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#f8fafc' }}>
                            {act.title}
                          </span>
                          {act.executed && (
                            <span className="badge badge-safe" style={{ fontSize: '0.6rem', padding: '1px 6px' }}>
                              Auto-Executed
                            </span>
                          )}
                        </div>
                        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                          {act.description}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* MITRE ATT&CK Techniques */}
              {result.mitre_attack_techniques.length > 0 && (
                <div style={{ paddingTop: '10px', borderTop: '1px solid var(--border-subtle)' }}>
                  <span style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', display: 'block', marginBottom: '6px' }}>
                    MITRE ATT&CK TECHNIQUES
                  </span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {result.mitre_attack_techniques.map((tech, i) => (
                      <span key={i} style={{
                        padding: '3px 8px',
                        backgroundColor: 'rgba(139, 92, 246, 0.12)',
                        border: '1px solid rgba(139, 92, 246, 0.3)',
                        borderRadius: '4px',
                        fontSize: '0.72rem',
                        fontFamily: 'var(--font-mono)',
                        color: '#c084fc'
                      }}>
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--text-muted)',
              textAlign: 'center',
              padding: '40px'
            }}>
              <ShieldAlert size={48} strokeWidth={1.2} style={{ marginBottom: '16px', opacity: 0.4 }} />
              <p style={{ fontSize: '0.9rem', fontWeight: 600 }}>Awaiting Phishing Threat Inspection</p>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '4px', maxWidth: '300px' }}>
                Select a preset sample above or paste custom email/SMS content to run the AI detection and explanation pipeline.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
