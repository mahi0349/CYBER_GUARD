import React, { useState } from 'react';
import {
  Activity,
  FileSpreadsheet,
  AlertTriangle,
  Bot,
  Shield,
  CheckCircle2,
  Lock,
  UserX,
  Smartphone,
  Loader2,
  Terminal
} from 'lucide-react';
import { analyzeLoginLog } from '../services/api';
import { AnalysisResponse } from '../types';
import { RiskScoreMeter } from '../components/dashboard/RiskScoreMeter';
import { SeverityBadge } from '../components/dashboard/SeverityBadge';
import { EvidenceList } from '../components/dashboard/EvidenceList';
import { MitreBadge } from '../components/dashboard/MitreBadge';

export const BehaviorAnalyzer: React.FC = () => {
  const [userId, setUserId] = useState('U1003');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const sampleEvents = [
    { time: '03:15:10', ip: '185.220.101.5', location: 'Tor Relay (Frankfurt, DE)', device: 'Headless Linux', status: 'FAILED (14x)', ua: 'Python-urllib/3.9' },
    { time: '03:18:22', ip: '185.220.101.5', location: 'Tor Relay (Frankfurt, DE)', device: 'Headless Linux', status: 'FAILED (15x)', ua: 'Python-urllib/3.9' },
    { time: '03:21:45', ip: '185.220.101.5', location: 'Tor Relay (Frankfurt, DE)', device: 'Headless Linux', status: 'SUCCESS (Compromise)', ua: 'curl/7.68.0' },
  ];

  const handleRunAnalysis = async () => {
    setLoading(true);
    setActionNotice(null);
    try {
      const res = await analyzeLoginLog(userId);
      setResult(res);
    } catch (err) {
      console.error('Error analyzing behavior:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
              <span>BEHAVIORAL ANOMALY & ACCOUNT TAKEOVER DETECTOR</span>
              <span className="text-xs px-2 py-0.5 rounded font-mono bg-amber-500/20 text-amber-300 border border-amber-500/30">
                SCENARIO 3
              </span>
            </h1>
            <p className="text-xs text-slate-400 font-mono">
              Unsupervised Isolation Forest + Multi-Factor Velocity & Geospatial Telemetry
            </p>
          </div>
        </div>
      </div>

      {/* Account Context & Event Stream Preview */}
      <div className="cyber-panel rounded-xl p-6 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-slate-400 uppercase">Target User Subject:</span>
            <input
              type="text"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 font-mono text-xs text-cyan-300 font-bold outline-none focus:border-cyan-500"
            />
            <span className="text-[11px] font-mono text-slate-500">Corporate Employee Identity</span>
          </div>

          <button
            onClick={handleRunAnalysis}
            disabled={loading}
            className="px-5 py-2.5 rounded-lg bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 disabled:opacity-50 text-white font-mono font-semibold text-xs flex items-center gap-2 shadow-lg shadow-amber-500/20 transition-all shrink-0"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>EVALUATING ISOLATION FOREST...</span>
              </>
            ) : (
              <>
                <FileSpreadsheet className="w-4 h-4" />
                <span>ANALYZE AUTH AUDIT LOG</span>
              </>
            )}
          </button>
        </div>

        {/* Incoming Telemetry Log Stream */}
        <div>
          <div className="text-xs font-mono font-semibold text-slate-400 uppercase mb-2 flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>Ingested Authentication Stream (Tor Velocity Burst)</span>
          </div>
          <div className="overflow-x-auto rounded-lg border border-slate-800">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 text-[10px] uppercase">
                <tr>
                  <th className="p-2.5">Timestamp</th>
                  <th className="p-2.5">Source IP</th>
                  <th className="p-2.5">Geographic Location</th>
                  <th className="p-2.5">Hardware Profile</th>
                  <th className="p-2.5">Auth Status</th>
                  <th className="p-2.5">Client User-Agent</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
                {sampleEvents.map((ev, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/50">
                    <td className="p-2.5 text-slate-300">{ev.time}</td>
                    <td className="p-2.5 text-cyan-300">{ev.ip}</td>
                    <td className="p-2.5 text-amber-300">{ev.location}</td>
                    <td className="p-2.5 text-slate-400">{ev.device}</td>
                    <td className="p-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        ev.status.includes('SUCCESS')
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                      }`}>
                        {ev.status}
                      </span>
                    </td>
                    <td className="p-2.5 text-slate-500 truncate max-w-[140px]" title={ev.ua}>
                      {ev.ua}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Analysis Result */}
      {result && (
        <div className="cyber-panel rounded-xl p-6 border-amber-500/30 space-y-6">
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 pb-6 border-b border-slate-800">
            <div className="space-y-2">
              <div className="flex items-center gap-3 flex-wrap">
                <SeverityBadge severity={result.severity} size="lg" />
                <MitreBadge technique={result.mitre_technique || 'T1078'} name={result.mitre_name || 'Valid Accounts'} />
                <span className="text-xs font-mono text-slate-400">
                  Target Account: <strong className="text-white">{userId}</strong>
                </span>
              </div>
              <h3 className="text-lg font-mono font-bold text-white">
                Account Takeover & Credential Abuse Anomaly
              </h3>
            </div>

            <div className="flex items-center gap-6 self-center lg:self-auto shrink-0">
              <div className="text-center font-mono">
                <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-1">
                  Anomaly Confidence
                </div>
                <div className="text-2xl font-bold text-amber-400">
                  {(result.confidence * 100).toFixed(0)}%
                </div>
                <div className="text-[10px] text-slate-400">Isolation Forest</div>
              </div>

              <div className="h-10 w-[1px] bg-slate-800" />

              <RiskScoreMeter score={result.risk_score} severity={result.severity} size="lg" />
            </div>
          </div>

          {/* AI Narrative */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-purple-500/30">
            <div className="flex items-center gap-2 text-purple-400 text-xs font-mono font-semibold mb-2">
              <Bot className="w-4 h-4" />
              <span>SOC EXPLANATION (GEMINI 3.8 / 2.0 FLASH)</span>
            </div>
            <p className="text-xs font-mono text-slate-200 leading-relaxed">
              {result.explanation}
            </p>
          </div>

          {/* Indicators list */}
          <EvidenceList evidence={result.evidence} title="Detected Behavioral Anomalies & Policy Breaches" />

          {/* Containment Buttons */}
          <div className="pt-6 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <span className="text-xs font-mono font-semibold text-slate-300 block">
                Automated Incident Containment Actions:
              </span>
              <span className="text-[11px] text-slate-400">
                Immediately isolate compromised user token and lock perimeter ingress
              </span>
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <button
                onClick={() => setActionNotice('Session Revocation Token issued: All active bearer tokens invalidated.')}
                className="px-3 py-1.5 rounded-lg bg-red-600/20 hover:bg-red-600/30 border border-red-500/40 text-red-300 text-xs font-mono font-semibold transition-colors flex items-center gap-1.5"
              >
                <UserX className="w-3.5 h-3.5" />
                <span>REVOKE SESSIONS</span>
              </button>
              <button
                onClick={() => setActionNotice('Step-up MFA enforced on Account U1003. Hardware FIDO2 token challenged.')}
                className="px-3 py-1.5 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 border border-amber-500/40 text-amber-300 text-xs font-mono font-semibold transition-colors flex items-center gap-1.5"
              >
                <Smartphone className="w-3.5 h-3.5" />
                <span>REQUIRE MFA</span>
              </button>
              <button
                onClick={() => setActionNotice('Ingress drop rule pushed: IP 185.220.101.5 blocked on border gateway.')}
                className="px-3 py-1.5 rounded-lg bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/40 text-purple-300 text-xs font-mono font-semibold transition-colors flex items-center gap-1.5"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>BLOCK SOURCE IP</span>
              </button>
            </div>
          </div>

          {actionNotice && (
            <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center gap-2 animate-fadeIn">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>
                <strong>CONTAINMENT ACTIVE:</strong> {actionNotice} Incident status updated to <strong>CONTAINED</strong>.
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
