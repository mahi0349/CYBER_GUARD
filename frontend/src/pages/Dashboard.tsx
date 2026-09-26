import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Zap,
  Activity,
  AlertTriangle,
  MailWarning,
  UserCheck,
  CheckCircle2,
  ExternalLink,
  RefreshCw
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell
} from 'recharts';

import { StatCard } from '../components/dashboard/StatCard';
import { SeverityBadge } from '../components/dashboard/SeverityBadge';
import { ThreatBadge } from '../components/dashboard/ThreatBadge';
import { MitreBadge } from '../components/dashboard/MitreBadge';
import { DashboardStats } from '../types';
import { fetchDashboardStats } from '../services/api';

interface DashboardProps {
  onNavigate: (tab: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ onNavigate }) => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  const loadStats = async () => {
    setLoading(true);
    const data = await fetchDashboardStats();
    setStats(data);
    setLoading(false);
  };

  useEffect(() => {
    loadStats();
    const interval = setInterval(loadStats, 15000); // refresh every 15s
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="flex flex-col items-center gap-3">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
          <p className="text-sm font-mono text-slate-400">Loading CYBERGUARD telemetry...</p>
        </div>
      </div>
    );
  }

  const s = stats!;

  // Prepare chart data
  const severityChartData = [
    { name: 'CRITICAL', count: s.severity_distribution?.CRITICAL || 18, color: '#ef4444' },
    { name: 'HIGH', count: s.severity_distribution?.HIGH || 43, color: '#f97316' },
    { name: 'MEDIUM', count: s.severity_distribution?.MEDIUM || 38, color: '#eab308' },
    { name: 'LOW', count: s.severity_distribution?.LOW || 24, color: '#3b82f6' },
    { name: 'SAFE', count: s.severity_distribution?.SAFE || 14, color: '#10b981' },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner with live timestamp and refresh */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2.5">
            <span>SOC COMMAND CENTER</span>
            <span className="text-xs px-2 py-0.5 rounded font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
              TIER-3 ACTIVE
            </span>
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Real-time Threat Telemetry, Deterministic Scoring & Autonomous Containment
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={loadStats}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700/80 hover:border-cyan-500/40 text-xs font-mono text-slate-300 transition-all"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>REFRESH</span>
          </button>
          <button
            onClick={() => onNavigate('scanner')}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-xs font-mono font-semibold text-white shadow-lg shadow-cyan-500/20 transition-all"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>LAUNCH SCANNER</span>
          </button>
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Events Analyzed"
          value={s.total_events_analyzed.toLocaleString()}
          change="+14.2% today"
          isPositive={true}
          icon={Activity}
          color="cyan"
        />
        <StatCard
          title="Threats Detected"
          value={s.threats_detected}
          change="+6 new"
          isPositive={false}
          icon={ShieldAlert}
          color="amber"
        />
        <StatCard
          title="Critical Threats"
          value={s.critical_threats}
          change="Urgent Action"
          isPositive={false}
          icon={AlertTriangle}
          color="red"
        />
        <StatCard
          title="Active Incidents"
          value={s.active_incidents}
          change="3 Contained"
          isPositive={true}
          icon={CheckCircle2}
          color="blue"
        />
      </div>

      {/* Threat Activity Trends & Severity Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Timeline Area Chart */}
        <div className="lg:col-span-2 cyber-panel rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-mono font-bold text-white uppercase tracking-wider">
                Threat Activity Over Time
              </h3>
              <p className="text-xs text-slate-400">7-Day Aggregated Vector Ingestion</p>
            </div>
            <div className="flex items-center gap-3 text-xs font-mono">
              <span className="flex items-center gap-1 text-red-400">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" /> Phishing
              </span>
              <span className="flex items-center gap-1 text-purple-400">
                <span className="w-2.5 h-2.5 rounded-full bg-purple-500 inline-block" /> Deepfake
              </span>
              <span className="flex items-center gap-1 text-amber-400">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" /> Takeover
              </span>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={s.timeline} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="phishGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="deepfakeGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#a855f7" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#a855f7" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="atoGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="day" stroke="#64748b" fontSize={11} fontFamily="monospace" />
                <YAxis stroke="#64748b" fontSize={11} fontFamily="monospace" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                    fontFamily: 'monospace'
                  }}
                />
                <Area type="monotone" dataKey="phishing" stroke="#ef4444" fillOpacity={1} fill="url(#phishGrad)" />
                <Area type="monotone" dataKey="deepfake" stroke="#a855f7" fillOpacity={1} fill="url(#deepfakeGrad)" />
                <Area type="monotone" dataKey="account_takeover" stroke="#f59e0b" fillOpacity={1} fill="url(#atoGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="cyber-panel rounded-xl p-5 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-mono font-bold text-white uppercase tracking-wider mb-1">
              Severity Distribution
            </h3>
            <p className="text-xs text-slate-400 mb-4">Risk Engine Policy Categorization</p>

            <div className="h-48 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityChartData} margin={{ top: 10, right: 0, left: -25, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="name" stroke="#64748b" fontSize={10} fontFamily="monospace" />
                  <YAxis stroke="#64748b" fontSize={10} fontFamily="monospace" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '12px',
                      fontFamily: 'monospace'
                    }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {severityChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-2 pt-3 border-t border-slate-800 text-center font-mono">
            <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
              <div className="text-[10px] text-slate-400">PHISHING</div>
              <div className="text-lg font-bold text-red-400">{s.phishing_count}</div>
            </div>
            <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
              <div className="text-[10px] text-slate-400">DEEPFAKE</div>
              <div className="text-lg font-bold text-purple-400">{s.deepfake_count}</div>
            </div>
            <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
              <div className="text-[10px] text-slate-400">TAKEOVER</div>
              <div className="text-lg font-bold text-amber-400">{s.account_takeover_count}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Live Recent Threats & Active Incidents Split */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Detected Threats */}
        <div className="cyber-panel rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                <span>Recent Threat Detections</span>
              </h3>
              <p className="text-xs text-slate-400">Calculated composite risk scores from ML + Rules</p>
            </div>
            <button
              onClick={() => onNavigate('phishing')}
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              <span>Scan Target</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>

          <div className="divide-y divide-slate-800/80 space-y-3">
            {s.recent_threats.slice(0, 4).map((t) => (
              <div key={t.id} className="pt-3 first:pt-0 flex items-center justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <ThreatBadge type={t.threat_type} />
                    <SeverityBadge severity={t.severity} />
                    <span className="text-[10px] font-mono text-slate-500">
                      {new Date(t.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                  <p className="text-xs font-mono text-slate-300 truncate mt-1.5" title={t.source_payload}>
                    {t.source_payload || 'Threat payload'}
                  </p>
                </div>

                <div className="text-right shrink-0">
                  <div className="text-lg font-mono font-bold text-white">
                    {t.risk_score}<span className="text-xs text-slate-500">/100</span>
                  </div>
                  <span className="text-[10px] font-mono text-cyan-400">
                    {(t.confidence * 100).toFixed(0)}% Conf
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Active Incidents & Containment */}
        <div className="cyber-panel rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <span>Active Incident Triage</span>
              </h3>
              <p className="text-xs text-slate-400">MITRE ATT&CK Mapped Containment Queue</p>
            </div>
            <button
              onClick={() => onNavigate('incidents')}
              className="text-xs font-mono text-red-400 hover:text-red-300 flex items-center gap-1"
            >
              <span>View All</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>

          <div className="divide-y divide-slate-800/80 space-y-3">
            {s.recent_incidents.slice(0, 4).map((inc) => (
              <div key={inc.id} className="pt-3 first:pt-0 flex items-center justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-xs font-bold text-cyan-400">
                      {inc.incident_code}
                    </span>
                    <MitreBadge technique={inc.mitre_technique} />
                    <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${
                      inc.status === 'CONTAINED'
                        ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                        : 'bg-red-500/20 text-red-400 border-red-500/30'
                    }`}>
                      {inc.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-200 font-medium truncate mt-1">
                    {inc.title}
                  </p>
                </div>

                <button
                  onClick={() => onNavigate('incidents')}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-red-950 hover:text-red-300 hover:border-red-500/40 border border-slate-700 text-xs font-mono text-slate-300 transition-colors"
                >
                  Triage
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
