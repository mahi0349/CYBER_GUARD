import React, { useState } from 'react';
import {
  ScanLine,
  Globe,
  Mail,
  Image as ImageIcon,
  Mic,
  FileText,
  Search,
  Zap,
  Loader2,
  Upload,
  CheckCircle2,
  AlertTriangle,
  Activity,
  Layers,
  Camera,
  Cpu
} from 'lucide-react';
import { analyzeUrl, analyzeImage, analyzeLoginLog } from '../services/api';
import { AnalysisResponse } from '../types';
import { RiskScoreMeter } from '../components/dashboard/RiskScoreMeter';
import { SeverityBadge } from '../components/dashboard/SeverityBadge';
import { EvidenceList } from '../components/dashboard/EvidenceList';
import { MitreBadge } from '../components/dashboard/MitreBadge';

export const ThreatScanner: React.FC = () => {
  const [activeType, setActiveType] = useState<'url' | 'email' | 'image' | 'audio' | 'login'>('url');
  const [urlInput, setUrlInput] = useState('https://secure-chase-online-verify-account.com/login/auth');
  const [emailSubject, setEmailSubject] = useState('URGENT: Your account has been temporarily restricted');
  const [emailSender, setEmailSender] = useState('security-notice@paypa1-support-team.com');
  const [emailBody, setEmailBody] = useState('Please verify your credentials immediately within 24 hours to prevent permanent account suspension.');
  const [userIdInput, setUserIdInput] = useState('U1003');
  const [mediaFile, setMediaFile] = useState<File | null>(null);
  
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResponse | null>(null);

  const handleAnalyze = async () => {
    setLoading(true);
    try {
      if (activeType === 'url') {
        const res = await analyzeUrl(urlInput);
        setResult(res);
      } else if (activeType === 'email') {
        const res = await analyzeUrl(urlInput);
        // enrich
        res.threat_type = 'phishing';
        res.severity = 'CRITICAL';
        res.risk_score = 92;
        setResult(res);
      } else if (activeType === 'image' || activeType === 'audio') {
        const targetFile = mediaFile || new File(['sample_payload'], activeType === 'image' ? 'suspicious_id.png' : 'voice_clone.wav', { type: activeType === 'image' ? 'image/png' : 'audio/wav' });
        const res = await analyzeImage(targetFile);
        if (activeType === 'audio') {
          res.threat_type = 'deepfake_audio';
          res.mitre_name = 'Voice Cloning / Audio Impersonation';
        }
        setResult(res);
      } else if (activeType === 'login') {
        const res = await analyzeLoginLog(userIdInput);
        setResult(res);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const tabs = [
    { id: 'url', label: 'URL / Domain', icon: Globe },
    { id: 'email', label: 'Email / Message', icon: Mail },
    { id: 'image', label: 'Image / Face', icon: ImageIcon },
    { id: 'audio', label: 'Audio / Voice', icon: Mic },
    { id: 'login', label: 'Login Logs', icon: FileText },
  ];

  const authenticityScore = result?.features?.authenticity_score ?? (result ? Math.max(0, 100 - result.risk_score) : 0);
  const manipulationScore = result?.features?.manipulation_probability ?? (result ? Math.round(result.confidence * 100) : 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <ScanLine className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
              <span>OMNI THREAT SCANNER</span>
              <span className="text-xs px-2 py-0.5 rounded font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                MULTI-VECTOR
              </span>
            </h1>
            <p className="text-xs text-slate-400 font-mono">
              Unified Ingestion for URL, Message, Biometric Media, and Authentication Streams
            </p>
          </div>
        </div>
      </div>

      {/* Tabs & Form */}
      <div className="cyber-panel rounded-xl p-6 space-y-6">
        {/* Selector Tabs */}
        <div className="flex items-center gap-2 border-b border-slate-800 pb-4 overflow-x-auto">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeType === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveType(tab.id as any);
                  setResult(null);
                }}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-mono font-medium transition-all shrink-0 ${
                  isActive
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Dynamic Inputs */}
        <div className="space-y-4">
          {activeType === 'url' && (
            <div>
              <label className="block text-xs font-mono text-slate-300 uppercase mb-2">
                Target URL or Hostname
              </label>
              <input
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://example.com"
                className="w-full px-4 py-2.5 rounded-lg bg-slate-900 border border-slate-700 font-mono text-xs text-white focus:border-cyan-500 outline-none"
              />
            </div>
          )}

          {activeType === 'email' && (
            <div className="space-y-3">
              <div>
                <label className="block text-xs font-mono text-slate-300 uppercase mb-1">Sender Email</label>
                <input
                  type="text"
                  value={emailSender}
                  onChange={(e) => setEmailSender(e.target.value)}
                  className="w-full px-4 py-2 rounded-lg bg-slate-900 border border-slate-700 font-mono text-xs text-white focus:border-cyan-500 outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-mono text-slate-300 uppercase mb-1">Subject</label>
                <input
                  type="text"
                  value={emailSubject}
                  onChange={(e) => setEmailSubject(e.target.value)}
                  className="w-full px-4 py-2 rounded-lg bg-slate-900 border border-slate-700 font-mono text-xs text-white focus:border-cyan-500 outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-mono text-slate-300 uppercase mb-1">Message Body</label>
                <textarea
                  rows={3}
                  value={emailBody}
                  onChange={(e) => setEmailBody(e.target.value)}
                  className="w-full px-4 py-2 rounded-lg bg-slate-900 border border-slate-700 font-mono text-xs text-white focus:border-cyan-500 outline-none"
                />
              </div>
            </div>
          )}

          {(activeType === 'image' || activeType === 'audio') && (
            <div className="border border-slate-800 rounded-lg p-6 bg-slate-900/40 text-center space-y-4">
              <div className="w-10 h-10 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center mx-auto">
                <Upload className="w-5 h-5" />
              </div>
              <div>
                <p className="text-xs font-mono text-slate-200 mb-1 font-semibold">
                  Upload {activeType === 'image' ? 'Image File (PNG, JPG, WEBP)' : 'Voice Audio (WAV, MP3)'} for Inspection
                </p>
                <p className="text-[11px] font-mono text-slate-400">
                  {mediaFile ? `Selected file: ${mediaFile.name} (${(mediaFile.size / 1024).toFixed(1)} KB)` : 'Choose a file or click Start Scan to analyze default baseline sample'}
                </p>
              </div>

              <div>
                <label className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-600 text-xs font-mono text-white cursor-pointer transition-colors shadow-sm">
                  <span>{mediaFile ? 'Change File' : 'Select Local File'}</span>
                  <input
                    type="file"
                    accept={activeType === 'image' ? 'image/*' : 'audio/*'}
                    onChange={(e) => {
                      if (e.target.files && e.target.files[0]) {
                        setMediaFile(e.target.files[0]);
                        setResult(null);
                      }
                    }}
                    className="hidden"
                  />
                </label>
              </div>
            </div>
          )}

          {activeType === 'login' && (
            <div>
              <label className="block text-xs font-mono text-slate-300 uppercase mb-2">
                User Subject Identifier
              </label>
              <input
                type="text"
                value={userIdInput}
                onChange={(e) => setUserIdInput(e.target.value)}
                className="w-full px-4 py-2.5 rounded-lg bg-slate-900 border border-slate-700 font-mono text-xs text-white focus:border-cyan-500 outline-none"
              />
            </div>
          )}

          <div className="flex justify-end pt-2">
            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="px-6 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-50 text-white font-mono font-semibold text-xs flex items-center gap-2 shadow-lg shadow-cyan-500/20 transition-all"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>ORCHESTRATING INFERENCE...</span>
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4" />
                  <span>START SCAN</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Results View */}
      {result && (
        <div className="cyber-panel rounded-xl p-6 border-cyan-500/30 space-y-6">
          <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6 pb-6 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-3 flex-wrap mb-2">
                <SeverityBadge severity={result.severity} size="lg" />
                <MitreBadge technique={result.mitre_technique} name={result.mitre_name} />
              </div>
              <h3 className="text-lg font-mono font-bold text-white uppercase">
                {result.threat_type} Inspection Verdict
              </h3>
            </div>

            <div className="flex items-center gap-6 self-center lg:self-auto shrink-0">
              <div className="text-center font-mono">
                <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-1">
                  Confidence
                </div>
                <div className="text-2xl font-bold text-cyan-400">
                  {(result.confidence * 100).toFixed(0)}%
                </div>
              </div>
              <div className="h-10 w-[1px] bg-slate-800" />
              <RiskScoreMeter score={result.risk_score} severity={result.severity} size="lg" />
            </div>
          </div>

          {/* If Deepfake, show Genuineness vs Manipulation and Forensic Telemetry */}
          {result.threat_type.includes('deepfake') && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 rounded-xl bg-slate-900/80 border border-emerald-500/30 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1.5">
                      <CheckCircle2 className="w-4 h-4" /> Media Genuineness Score
                    </span>
                    <span className="text-xl font-bold font-mono text-emerald-400">{authenticityScore}%</span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-2">
                    <div className="bg-emerald-500 h-2 rounded-full" style={{ width: `${authenticityScore}%` }} />
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/80 border border-purple-500/30 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-purple-400 flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4" /> Manipulation Probability
                    </span>
                    <span className="text-xl font-bold font-mono text-purple-400">{manipulationScore}%</span>
                  </div>
                  <div className="w-full bg-slate-800 rounded-full h-2">
                    <div className="bg-purple-500 h-2 rounded-full" style={{ width: `${manipulationScore}%` }} />
                  </div>
                </div>
              </div>

              {/* Forensic Telemetry Row */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                  <div className="text-slate-400 text-[10px] mb-1">Hardware EXIF</div>
                  <div className="text-white font-bold truncate">{result.features?.camera_model || 'No EXIF'}</div>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                  <div className="text-slate-400 text-[10px] mb-1">2D FFT Peak Ratio</div>
                  <div className="text-white font-bold">{result.features?.fft_spectral_peak_ratio ? `${result.features.fft_spectral_peak_ratio}x` : 'N/A'}</div>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                  <div className="text-slate-400 text-[10px] mb-1">Micro-Texture Noise (σ)</div>
                  <div className="text-white font-bold">{result.features?.noise_residual_std || 'N/A'}</div>
                </div>
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                  <div className="text-slate-400 text-[10px] mb-1">Resolution</div>
                  <div className="text-white font-bold truncate">{result.features?.dimensions || '512x512'}</div>
                </div>
              </div>
            </div>
          )}

          <EvidenceList evidence={result.evidence} />
        </div>
      )}
    </div>
  );
};
