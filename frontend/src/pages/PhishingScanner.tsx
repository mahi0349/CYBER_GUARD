import React, { useState } from 'react';
import {
  MailWarning,
  Search,
  CheckCircle2,
  AlertOctagon,
  Sparkles,
  Bot,
  Shield,
  Send,
  Loader2,
  Copy,
  Check
} from 'lucide-react';
import { analyzeUrl } from '../services/api';
import { AnalysisResponse } from '../types';
import { RiskScoreMeter } from '../components/dashboard/RiskScoreMeter';
import { SeverityBadge } from '../components/dashboard/SeverityBadge';
import { EvidenceList } from '../components/dashboard/EvidenceList';
import { MitreBadge } from '../components/dashboard/MitreBadge';

export const PhishingScanner: React.FC = () => {
  const [url, setUrl] = useState('https://secure-chase-online-verify-account.com/login/auth?token=928348');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [actionSimulated, setActionSimulated] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const handleScan = async (targetUrl?: string) => {
    const scanTarget = targetUrl || url;
    if (!scanTarget) return;
    setLoading(true);
    setActionSimulated(null);
    try {
      const res = await analyzeUrl(scanTarget);
      setResult(res);
    } catch (err) {
      console.error('Scan error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const sampleUrls = [
    {
      label: '🔴 Critical Banking Phish',
      url: 'https://secure-chase-online-verify-account.com/login/auth?token=928348',
      type: 'critical'
    },
    {
      label: '🟢 Genuine Google Portal',
      url: 'https://accounts.google.com/signin/v2/identifier',
      type: 'safe'
    },
    {
      label: '🔴 IP-based Cloudflare Phish',
      url: 'http://192.168.1.105/cloudflare-challenge/session-verify.html',
      type: 'critical'
    },
    {
      label: '🟠 Microsoft 365 Spoof',
      url: 'https://login.microsoftonline.security-verify-tenant.net/common/oauth2',
      type: 'high'
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400">
            <MailWarning className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
              <span>PHISHING DETECTOR & LEXICAL ANALYZER</span>
              <span className="text-xs px-2 py-0.5 rounded font-mono bg-red-500/20 text-red-300 border border-red-500/30">
                SCENARIO 1
              </span>
            </h1>
            <p className="text-xs text-slate-400 font-mono">
              Deterministic Feature Extraction + Random Forest Classifier (96.2% Accuracy)
            </p>
          </div>
        </div>
      </div>

      {/* Input Box & Quick Samples */}
      <div className="cyber-panel rounded-xl p-5 space-y-4">
        <div>
          <label className="block text-xs font-mono font-semibold uppercase text-slate-300 mb-2">
            Target Suspicious URL / Link to Inspect
          </label>
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example-login-verify.com/auth"
                className="w-full px-4 py-2.5 rounded-lg bg-slate-900 border border-slate-700 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono text-sm text-white placeholder-slate-500 outline-none pr-10"
              />
              <button
                onClick={handleCopy}
                className="absolute right-2.5 top-2.5 text-slate-400 hover:text-slate-200"
                title="Copy URL"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
            <button
              onClick={() => handleScan()}
              disabled={loading}
              className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-red-600 to-pink-600 hover:from-red-500 hover:to-pink-500 disabled:opacity-50 text-white font-mono font-semibold text-xs flex items-center gap-2 shadow-lg shadow-red-500/20 transition-all shrink-0"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>ANALYZING...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>ANALYZE URL</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Quick Demo Test Presets */}
        <div>
          <span className="text-[11px] font-mono text-slate-400 block mb-2">
            Quick Test Scenarios (Click to test instantly):
          </span>
          <div className="flex flex-wrap gap-2">
            {sampleUrls.map((s, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setUrl(s.url);
                  handleScan(s.url);
                }}
                className="px-3 py-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-700/80 text-xs font-mono text-slate-300 transition-all hover:border-cyan-500/40"
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Analysis Result Card */}
      {result && (
        <div className="space-y-6">
          <div className="cyber-panel rounded-xl p-6 border-cyan-500/30">
            <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 pb-6 border-b border-slate-800">
              <div className="space-y-2">
                <div className="flex items-center gap-3 flex-wrap">
                  <SeverityBadge severity={result.severity} size="lg" />
                  <MitreBadge technique={result.mitre_technique || 'T1566'} name={result.mitre_name || 'Phishing'} />
                  <span className="text-xs font-mono text-slate-400">
                    Prediction: <strong className="text-white uppercase">{result.prediction}</strong>
                  </span>
                </div>
                <h3 className="text-lg font-mono font-bold text-white break-all">
                  {url}
                </h3>
              </div>

              {/* Score Meter & ML Confidence */}
              <div className="flex items-center gap-6 self-center lg:self-auto shrink-0">
                <div className="text-center font-mono">
                  <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-1">
                    ML Model Probability
                  </div>
                  <div className="text-2xl font-bold text-red-400">
                    {(result.confidence * 100).toFixed(0)}%
                  </div>
                  <div className="text-[10px] text-slate-400">Random Forest</div>
                </div>

                <div className="h-10 w-[1px] bg-slate-800" />

                <RiskScoreMeter score={result.risk_score} severity={result.severity} size="lg" />
              </div>
            </div>

            {/* Explainable AI Narrative */}
            <div className="my-6 p-4 rounded-xl bg-slate-900/90 border border-purple-500/30">
              <div className="flex items-center gap-2 text-purple-400 text-xs font-mono font-semibold mb-2">
                <Bot className="w-4 h-4" />
                <span>EXPLAINABLE AI REASONING (GEMINI 3.8 / 2.0 FLASH)</span>
              </div>
              <p className="text-xs font-mono text-slate-200 leading-relaxed">
                {result.explanation}
              </p>
            </div>

            {/* Forensic Indicators */}
            <EvidenceList evidence={result.evidence} />

            {/* Extracted Lexical Features Grid */}
            {result.features && (
              <div className="mt-6 pt-6 border-t border-slate-800">
                <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-400 mb-3">
                  Extracted Lexical & Structural Telemetry
                </h4>
                <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-2 font-mono text-xs">
                  {Object.entries(result.features).map(([k, v]) => (
                    <div key={k} className="p-2.5 rounded bg-slate-900/60 border border-slate-800">
                      <div className="text-[10px] text-slate-500 truncate uppercase">{k.replace(/_/g, ' ')}</div>
                      <div className="text-sm font-bold text-cyan-300 mt-0.5">{String(v)}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recommended Automated Containment Playbooks */}
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

            {/* Simulated execution alert */}
            {actionSimulated && (
              <div className="mt-4 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center gap-2 animate-fadeIn">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>
                  <strong>PLAYBOOK EXECUTED:</strong> {actionSimulated.replace(/_/g, ' ').toUpperCase()} successfully applied. Perimeter DNS sinkhole policy updated and incident queued.
                </span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
