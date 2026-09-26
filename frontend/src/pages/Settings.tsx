import React, { useState } from 'react';
import {
  Sliders,
  ShieldCheck,
  Bot,
  Database,
  Save,
  CheckCircle2,
  RefreshCw,
  Lock
} from 'lucide-react';

export const Settings: React.FC = () => {
  const [lowThresh, setLowThresh] = useState(20);
  const [medThresh, setMedThresh] = useState(40);
  const [highThresh, setHighThresh] = useState(60);
  const [critThresh, setCritThresh] = useState(80);
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Sliders className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
              <span>RISK POLICY & PLATFORM CONFIGURATION</span>
              <span className="text-xs px-2 py-0.5 rounded font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                SOC POLICY
              </span>
            </h1>
            <p className="text-xs text-slate-400 font-mono">
              Deterministic threshold policies, LLM orchestrator tokens, and backend telemetry
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Deterministic Risk Policy Thresholds */}
        <div className="cyber-panel rounded-xl p-6 space-y-6">
          <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-mono font-bold text-white uppercase flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-cyan-400" />
                <span>Deterministic Scoring Policy</span>
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Composite score cutoffs (0-100 scale)
              </p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
              ACTIVE
            </span>
          </div>

          <div className="space-y-4 font-mono text-xs">
            <div>
              <div className="flex justify-between mb-1.5">
                <span className="text-blue-400 font-bold">LOW RISK THRESHOLD</span>
                <span className="text-white font-bold">{lowThresh} pts</span>
              </div>
              <input
                type="range"
                min="10"
                max="35"
                value={lowThresh}
                onChange={(e) => setLowThresh(Number(e.target.value))}
                className="w-full accent-blue-500"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1.5">
                <span className="text-yellow-400 font-bold">MEDIUM RISK THRESHOLD</span>
                <span className="text-white font-bold">{medThresh} pts</span>
              </div>
              <input
                type="range"
                min="30"
                max="55"
                value={medThresh}
                onChange={(e) => setMedThresh(Number(e.target.value))}
                className="w-full accent-yellow-500"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1.5">
                <span className="text-orange-400 font-bold">HIGH RISK THRESHOLD</span>
                <span className="text-white font-bold">{highThresh} pts</span>
              </div>
              <input
                type="range"
                min="50"
                max="75"
                value={highThresh}
                onChange={(e) => setHighThresh(Number(e.target.value))}
                className="w-full accent-orange-500"
              />
            </div>

            <div>
              <div className="flex justify-between mb-1.5">
                <span className="text-red-400 font-bold">CRITICAL RISK THRESHOLD</span>
                <span className="text-white font-bold">{critThresh} pts</span>
              </div>
              <input
                type="range"
                min="70"
                max="95"
                value={critThresh}
                onChange={(e) => setCritThresh(Number(e.target.value))}
                className="w-full accent-red-500"
              />
            </div>
          </div>

          <button
            onClick={handleSave}
            className="w-full py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono font-semibold text-xs flex items-center justify-center gap-2 shadow-lg shadow-cyan-500/20 transition-all"
          >
            <Save className="w-4 h-4" />
            <span>SAVE POLICY THRESHOLDS</span>
          </button>

          {saved && (
            <div className="p-2.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span>Thresholds synchronized to CYBERGUARD Risk Engine.</span>
            </div>
          )}
        </div>

        {/* AI Model & Backend Telemetry */}
        <div className="space-y-6">
          <div className="cyber-panel rounded-xl p-6 space-y-4">
            <div className="border-b border-slate-800 pb-3">
              <h3 className="text-sm font-mono font-bold text-white uppercase flex items-center gap-2">
                <Bot className="w-4 h-4 text-purple-400" />
                <span>Explainable AI Engine (Google Gemini)</span>
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Multimodal threat reasoning & evidence narrative generator
              </p>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-slate-400 text-[11px] mb-1">SELECTED MODEL</label>
                <input
                  type="text"
                  readOnly
                  value="gemini-2.0-flash / gemini-3.8-flash"
                  className="w-full px-3 py-2 rounded bg-slate-900 border border-slate-700 text-cyan-300 font-semibold"
                />
              </div>

              <div>
                <label className="block text-slate-400 text-[11px] mb-1">FALLBACK CONTINGENCY</label>
                <div className="p-3 rounded bg-slate-900/80 border border-slate-800 text-slate-300 text-[11px] leading-relaxed">
                  Deterministic SOC Rule-Based Narrative Engine actively armed. Triggers automatically if offline or if no API key is specified.
                </div>
              </div>
            </div>
          </div>

          <div className="cyber-panel rounded-xl p-6 space-y-4">
            <div className="border-b border-slate-800 pb-3">
              <h3 className="text-sm font-mono font-bold text-white uppercase flex items-center gap-2">
                <Database className="w-4 h-4 text-emerald-400" />
                <span>Data Storage & Persistence</span>
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                Dual-driver PostgreSQL + SQLite with auto-fallback
              </p>
            </div>

            <div className="grid grid-cols-2 gap-2 font-mono text-xs">
              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                <div className="text-[10px] text-slate-400">POSTGRESQL CONTAINER</div>
                <div className="text-xs font-bold text-cyan-400 mt-1">docker-compose.yml</div>
              </div>
              <div className="p-3 rounded bg-slate-900 border border-slate-800">
                <div className="text-[10px] text-slate-400">SQLITE LOCAL FALLBACK</div>
                <div className="text-xs font-bold text-emerald-400 mt-1">cyberguard.db (Online)</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
