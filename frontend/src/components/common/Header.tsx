import React from 'react';
import { Shield, Radio, Bell, Terminal, AlertTriangle } from 'lucide-react';

interface HeaderProps {
  activeIncidentsCount?: number;
}

export const Header: React.FC<HeaderProps> = ({ activeIncidentsCount = 23 }) => {
  return (
    <header className="h-16 border-b border-slate-800/80 bg-[#0a0f1d]/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-50">
      {/* Brand & Status */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 ring-1 ring-cyan-400/40">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-lg tracking-wider text-white">QuantumVault</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">AI DEFENSE</span>
            </div>
            <p className="text-[11px] text-slate-400 -mt-0.5 font-mono">SOC Threat Detection & Automated Response</p>
          </div>
        </div>

        {/* Live Radar Pulse Indicator */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono ml-4">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          ORCHESTRATOR LIVE
        </div>
      </div>

      {/* Right Stats & Controls */}
      <div className="flex items-center gap-4">
        {/* Incident Alert Pill */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs font-mono">
          <AlertTriangle className="w-3.5 h-3.5 animate-pulse text-red-400" />
          <span>{activeIncidentsCount} ACTIVE INCIDENTS</span>
        </div>

        {/* Live Terminal / Telemetry Button */}
        <div className="hidden sm:flex items-center gap-1.5 text-xs text-slate-400 font-mono bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-800">
          <Terminal className="w-3.5 h-3.5 text-cyan-400" />
          <span>FASTAPI / GEMINI 3.8</span>
        </div>

        {/* Analyst Avatar */}
        <div className="flex items-center gap-2.5 pl-2 border-l border-slate-800">
          <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-cyan-600 to-indigo-600 flex items-center justify-center font-bold text-xs text-white ring-2 ring-cyan-500/30">
            SA
          </div>
          <div className="hidden lg:block text-left">
            <div className="text-xs font-medium text-slate-200">SOC Analyst</div>
            <div className="text-[10px] font-mono text-cyan-400">Tier-3 Lead</div>
          </div>
        </div>
      </div>
    </header>
  );
};
