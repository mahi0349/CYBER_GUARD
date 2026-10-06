import React, { useState, useRef } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Upload,
  FileText,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
  Bot,
  Shield,
  Sparkles
} from 'lucide-react';
import { EmailAuthResult, EmailAuthFinding } from '../../types';
import { analyzeEmailAuth, SAMPLE_EMAILS } from '../../services/api';
import { RiskScoreMeter } from '../dashboard/RiskScoreMeter';
import { SeverityBadge } from '../dashboard/SeverityBadge';

// ── Auth Status Chip ─────────────────────────────────────────────────────
const AuthChip: React.FC<{ label: string; status: string }> = ({ label, status }) => {
  const lower = status.toLowerCase();
  const isPass = lower === 'pass';
  const isFail = ['fail', 'softfail', 'none'].includes(lower);

  let bg = 'bg-slate-700/40';
  let text = 'text-slate-400';
  let border = 'border-slate-600/40';
  let icon = <Info className="w-3.5 h-3.5" />;

  if (isPass) {
    bg = 'bg-emerald-500/15';
    text = 'text-emerald-400';
    border = 'border-emerald-500/40';
    icon = <CheckCircle2 className="w-3.5 h-3.5" />;
  } else if (isFail) {
    bg = 'bg-red-500/15';
    text = 'text-red-400';
    border = 'border-red-500/40';
    icon = <XCircle className="w-3.5 h-3.5" />;
  } else if (lower === 'missing') {
    bg = 'bg-amber-500/15';
    text = 'text-amber-400';
    border = 'border-amber-500/40';
    icon = <AlertTriangle className="w-3.5 h-3.5" />;
  }

  return (
    <div className={`flex items-center gap-2 px-3 py-2 rounded-lg ${bg} ${text} border ${border} font-mono text-xs font-semibold`}>
      {icon}
      <span className="uppercase tracking-wider">{label}</span>
      <span className="opacity-70">= {status.toUpperCase()}</span>
    </div>
  );
};

// ── Level badge colors ───────────────────────────────────────────────────
const levelToSeverity = (level: string): string => {
  const map: Record<string, string> = {
    'Safe': 'SAFE', 'Low': 'LOW', 'Medium': 'MEDIUM',
    'High': 'HIGH', 'Critical': 'CRITICAL',
  };
  return map[level] || 'SAFE';
};

// ── Finding status icon ─────────────────────────────────────────────────
const FindingIcon: React.FC<{ status: string }> = ({ status }) => {
  switch (status) {
    case 'pass': return <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />;
    case 'fail': return <XCircle className="w-4 h-4 text-red-400 shrink-0" />;
    case 'warn': return <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />;
    default: return <Info className="w-4 h-4 text-slate-400 shrink-0" />;
  }
};

// ── Main Component ──────────────────────────────────────────────────────
export const EmailAuthenticityPanel: React.FC = () => {
  const [rawText, setRawText] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<EmailAuthResult | null>(null);
  const [actionSimulated, setActionSimulated] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleAnalyze = async (sampleText?: string) => {
    const text = sampleText || rawText;
    if (!text.trim() && !fileInputRef.current?.files?.length) return;

    setLoading(true);
    setResult(null);
    setActionSimulated(null);

    try {
      const file = fileInputRef.current?.files?.[0];
      const res = await analyzeEmailAuth(file || undefined, file ? undefined : text);
      setResult(res);
    } catch (err) {
      console.error('Email auth analysis error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      // Also read the file text so the user can see it in the textarea
      const reader = new FileReader();
      reader.onload = (ev) => {
        setRawText(ev.target?.result as string || '');
      };
      reader.readAsText(file);
    }
  };

  const handleSampleClick = (key: keyof typeof SAMPLE_EMAILS) => {
    const text = SAMPLE_EMAILS[key];
    setRawText(text);
    // Reset file input
    if (fileInputRef.current) fileInputRef.current.value = '';
    handleAnalyze(text);
  };

  const samplePresets = [
    { key: 'clean' as const, label: '🟢 Clean Google Report', type: 'safe' },
    { key: 'spoofed' as const, label: '🔴 Spoofed CEO/Registrar', type: 'critical' },
    { key: 'lookalike' as const, label: '🔴 Lookalike SBI Bank', type: 'high' },
  ];

  // Group findings by auth category
  const getAuthFindings = (findings: EmailAuthFinding[]) => {
    const spf = findings.find(f => f.check === 'spf');
    const dkim = findings.find(f => f.check === 'dkim');
    const dmarc = findings.find(f => f.check === 'dmarc');
    return { spf, dkim, dmarc };
  };

  // Build comparison table data
  const getComparisonRows = (evidence: Record<string, any>) => {
    const fromDomain = evidence?.from_domain || '';
    const replyToDomain = evidence?.reply_to_domain || '';
    const returnPathDomain = evidence?.return_path_domain || '';

    return [
      { header: 'From', value: evidence?.from || '—', domain: fromDomain, mismatch: false },
      {
        header: 'Reply-To',
        value: evidence?.reply_to || '—',
        domain: replyToDomain,
        mismatch: replyToDomain && replyToDomain !== fromDomain,
      },
      {
        header: 'Return-Path',
        value: evidence?.return_path || '—',
        domain: returnPathDomain,
        mismatch: returnPathDomain && returnPathDomain !== fromDomain,
      },
    ];
  };

  return (
    <div className="space-y-6">
      {/* Input Section */}
      <div className="cyber-panel rounded-xl p-5 space-y-4">
        <div>
          <label className="block text-xs font-mono font-semibold uppercase text-slate-300 mb-2">
            Raw .eml Source / Email Headers
          </label>
          <textarea
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder="Paste raw .eml content or email headers here..."
            rows={6}
            className="w-full px-4 py-3 rounded-lg bg-slate-900 border border-slate-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono text-xs text-white placeholder-slate-500 outline-none resize-y"
          />
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {/* File upload */}
          <input
            ref={fileInputRef}
            type="file"
            accept=".eml,.txt,.msg"
            onChange={handleFileUpload}
            className="hidden"
            id="eml-file-input"
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            className="px-4 py-2 rounded-lg bg-slate-800/80 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs font-mono font-semibold flex items-center gap-2 transition-colors"
          >
            <Upload className="w-4 h-4" />
            <span>UPLOAD .EML</span>
          </button>

          {/* Analyze button */}
          <button
            onClick={() => handleAnalyze()}
            disabled={loading || (!rawText.trim() && !fileInputRef.current?.files?.length)}
            className="px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-white font-mono font-semibold text-xs flex items-center gap-2 shadow-lg shadow-cyan-500/20 transition-all"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>ANALYZING...</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4" />
                <span>ANALYZE AUTHENTICITY</span>
              </>
            )}
          </button>
        </div>

        {/* Quick Demo Presets */}
        <div>
          <span className="text-[11px] font-mono text-slate-400 block mb-2">
            Quick Test Scenarios (Click to test instantly):
          </span>
          <div className="flex flex-wrap gap-2">
            {samplePresets.map((s) => (
              <button
                key={s.key}
                onClick={() => handleSampleClick(s.key)}
                className="px-3 py-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-700/80 text-xs font-mono text-slate-300 transition-all hover:border-cyan-500/40"
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Results Section */}
      {result && (
        <div className="space-y-6 animate-fadeIn">
          {/* Score + Severity Header */}
          <div className="cyber-panel rounded-xl p-6 border-cyan-500/30">
            <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 pb-6 border-b border-slate-800">
              <div className="space-y-2">
                <div className="flex items-center gap-3 flex-wrap">
                  <SeverityBadge severity={levelToSeverity(result.level)} size="lg" />
                  <span className="px-2.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 uppercase tracking-wider">
                    T1566.001 — Email Spoofing
                  </span>
                </div>
                <h3 className="text-sm font-mono font-bold text-white">
                  Email Authenticity Assessment
                </h3>
                {result.evidence?.subject && (
                  <p className="text-xs font-mono text-slate-400 truncate max-w-md">
                    Subject: {result.evidence.subject}
                  </p>
                )}
              </div>

              <div className="flex items-center gap-6 self-center lg:self-auto shrink-0">
                <RiskScoreMeter score={result.score} severity={levelToSeverity(result.level)} size="lg" />
              </div>
            </div>

            {/* SPF / DKIM / DMARC Status Row */}
            <div className="mt-6">
              <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
                <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
                Authentication Protocol Status
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {(() => {
                  const { spf, dkim, dmarc } = getAuthFindings(result.findings);
                  return (
                    <>
                      <AuthChip label="SPF" status={result.evidence?.spf || spf?.status || 'missing'} />
                      <AuthChip label="DKIM" status={result.evidence?.dkim || dkim?.status || 'missing'} />
                      <AuthChip label="DMARC" status={result.evidence?.dmarc || dmarc?.status || 'missing'} />
                    </>
                  );
                })()}
              </div>
            </div>

            {/* From vs Reply-To vs Return-Path Comparison Table */}
            {result.evidence && (
              <div className="mt-6">
                <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
                  <FileText className="w-3.5 h-3.5 text-cyan-400" />
                  Sender Identity Comparison
                </h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs font-mono">
                    <thead>
                      <tr className="border-b border-slate-800">
                        <th className="text-left py-2 px-3 text-slate-400 uppercase tracking-wider">Header</th>
                        <th className="text-left py-2 px-3 text-slate-400 uppercase tracking-wider">Value</th>
                        <th className="text-left py-2 px-3 text-slate-400 uppercase tracking-wider">Domain</th>
                        <th className="text-left py-2 px-3 text-slate-400 uppercase tracking-wider">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {getComparisonRows(result.evidence).map((row) => (
                        <tr
                          key={row.header}
                          className={`border-b border-slate-800/50 ${row.mismatch ? 'bg-red-500/5' : ''}`}
                        >
                          <td className="py-2.5 px-3 text-slate-300 font-semibold">{row.header}</td>
                          <td className="py-2.5 px-3 text-slate-200 break-all max-w-xs">{row.value || '—'}</td>
                          <td className={`py-2.5 px-3 ${row.mismatch ? 'text-red-400 font-bold' : 'text-slate-300'}`}>
                            {row.domain || '—'}
                          </td>
                          <td className="py-2.5 px-3">
                            {row.mismatch ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30 text-[10px] font-semibold">
                                <XCircle className="w-3 h-3" />
                                MISMATCH
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 text-[10px] font-semibold">
                                <CheckCircle2 className="w-3 h-3" />
                                ALIGNED
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Explainable AI Narrative */}
            {result.explanation && (
              <div className="mt-6 p-4 rounded-xl bg-slate-900/90 border border-purple-500/30">
                <div className="flex items-center gap-2 text-purple-400 text-xs font-mono font-semibold mb-2">
                  <Bot className="w-4 h-4" />
                  <span>EXPLAINABLE AI REASONING (GEMINI 3.8 / 2.0 FLASH)</span>
                </div>
                <p className="text-xs font-mono text-slate-200 leading-relaxed">
                  {result.explanation}
                </p>
              </div>
            )}

            {/* "Why This Score" — All Findings */}
            <div className="mt-6">
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                  <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                  Why This Score — Detailed Findings
                </h4>
                <span className="text-[10px] font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
                  {result.findings.length} CHECKS PERFORMED
                </span>
              </div>

              <div className="space-y-2">
                {result.findings.map((finding, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-slate-900/80 border border-slate-800/90 hover:border-cyan-500/40 transition-all flex items-start justify-between gap-3"
                  >
                    <div className="flex items-start gap-2.5">
                      <FindingIcon status={finding.status} />
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-mono font-semibold text-cyan-300">
                            {finding.check.replace(/_/g, ' ').toUpperCase()}
                          </span>
                          <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${
                            finding.status === 'pass'
                              ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                              : finding.status === 'fail'
                              ? 'bg-red-500/15 text-red-400 border-red-500/30'
                              : finding.status === 'warn'
                              ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                              : 'bg-slate-700/40 text-slate-400 border-slate-600/40'
                          }`}>
                            {finding.status.toUpperCase()}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 mt-0.5 leading-relaxed">
                          {finding.detail}
                        </p>
                      </div>
                    </div>

                    {finding.weight > 0 && (
                      <span className="shrink-0 font-mono text-xs font-bold px-2 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30">
                        +{finding.weight} pts
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Recommended Actions */}
            <div className="mt-6 pt-6 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <span className="text-xs font-mono font-semibold text-slate-300 block">
                  Recommended SOC Containment Playbooks:
                </span>
                <span className="text-[11px] text-slate-400">
                  Simulated safe responses for hackathon demonstration
                </span>
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                {result.recommended_actions.map((act) => (
                  <button
                    key={act}
                    onClick={() => setActionSimulated(act)}
                    className="px-3 py-1.5 rounded-lg bg-red-600/20 hover:bg-red-600/30 border border-red-500/40 text-red-300 text-xs font-mono font-semibold transition-colors flex items-center gap-1.5"
                  >
                    <Shield className="w-3.5 h-3.5" />
                    <span>{act.replace(/_/g, ' ').toUpperCase()}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Simulated action alert */}
            {actionSimulated && (
              <div className="mt-4 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center gap-2 animate-fadeIn">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>
                  <strong>PLAYBOOK EXECUTED:</strong> {actionSimulated.replace(/_/g, ' ').toUpperCase()} successfully applied. Email quarantined and incident queued for SOC review.
                </span>
              </div>
            )}

            {/* Incident created badge */}
            {result.incident_id && (
              <div className="mt-4 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono flex items-center gap-2">
                <ShieldX className="w-4 h-4 text-amber-400 shrink-0" />
                <span>
                  <strong>INCIDENT CREATED:</strong> Threat ID #{result.threat_id} → Incident #{result.incident_id} automatically raised and assigned to SOC Lead Analyst.
                </span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
