import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Play,
  UserX,
  Lock,
  Smartphone,
  Ban,
  Filter,
  RefreshCw,
  Terminal
} from 'lucide-react';
import { fetchIncidents, executeIncidentAction } from '../services/api';
import { Incident } from '../types';
import { SeverityBadge } from '../components/dashboard/SeverityBadge';
import { MitreBadge } from '../components/dashboard/MitreBadge';

export const Incidents: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(true);
  const [executing, setExecuting] = useState(false);
  const [actionLog, setActionLog] = useState<string | null>(null);

  const loadIncidents = async () => {
    setLoading(true);
    const data = await fetchIncidents();
    setIncidents(data);
    if (data.length > 0 && !selectedIncident) {
      setSelectedIncident(data[0]);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadIncidents();
  }, []);

  const handleAction = async (actionType: string) => {
    if (!selectedIncident) return;
    setExecuting(true);
    try {
      const res = await executeIncidentAction(selectedIncident.id, actionType);
      setActionLog(res.result?.description || `Playbook ${actionType} triggered successfully.`);
      
      // Update local state
      setIncidents(prev => prev.map(inc => 
        inc.id === selectedIncident.id ? { ...inc, status: 'CONTAINED' } : inc
      ));
      setSelectedIncident(prev => prev ? { ...prev, status: 'CONTAINED' } : null);
    } catch (err) {
      console.error(err);
    } finally {
      setExecuting(false);
    }
  };

  const sampleTimeline = [
    { time: '10:21:04', event: 'Authentication failed (Invalid password)', source: '185.220.101.5 (Tor Relay)', status: 'fail' },
    { time: '10:22:18', event: 'Authentication failed (Invalid password)', source: '185.220.101.5 (Tor Relay)', status: 'fail' },
    { time: '10:23:02', event: 'Unregistered hardware device profile detected', source: 'Hardware Signature mismatch', status: 'warn' },
    { time: '10:23:45', event: 'Session initialized (Compromised token)', source: 'Automated Python Client', status: 'critical' },
    { time: '10:24:12', event: 'Unauthorized privilege escalation probe', source: '/admin/config endpoint access', status: 'critical' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
              <span>INCIDENT TRIAGE & AUTONOMOUS CONTAINMENT</span>
              <span className="text-xs px-2 py-0.5 rounded font-mono bg-red-500/20 text-red-300 border border-red-500/30">
                SOC ROOM
              </span>
            </h1>
            <p className="text-xs text-slate-400 font-mono">
              Live containment playbooks, forensic audit trails, and MITRE ATT&CK techniques
            </p>
          </div>
        </div>

        <button
          onClick={loadIncidents}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs font-mono text-slate-300 hover:border-cyan-500/40 transition-all self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>REFRESH INCIDENTS</span>
        </button>
      </div>

      {/* Main Grid: Incident List + Incident Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Incidents Queue */}
        <div className="lg:col-span-5 cyber-panel rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <span className="text-xs font-mono font-semibold uppercase text-slate-400">
              Active Security Tickets ({incidents.length})
            </span>
            <div className="flex items-center gap-1 text-[10px] font-mono text-slate-500">
              <Filter className="w-3 h-3" />
              <span>SORT: SEVERITY</span>
            </div>
          </div>

          <div className="space-y-2 max-h-[620px] overflow-y-auto pr-1">
            {incidents.map((inc) => {
              const isSelected = selectedIncident?.id === inc.id;
              return (
                <div
                  key={inc.id}
                  onClick={() => {
                    setSelectedIncident(inc);
                    setActionLog(null);
                  }}
                  className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-slate-800/90 border-cyan-500/50 shadow-md shadow-cyan-500/10'
                      : 'bg-slate-900/60 border-slate-800/80 hover:border-slate-700 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-cyan-400">
                        {inc.incident_code}
                      </span>
                      <SeverityBadge severity={inc.severity} />
                    </div>
                    <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${
                      inc.status === 'CONTAINED'
                        ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                        : 'bg-red-500/20 text-red-400 border-red-500/30'
                    }`}>
                      {inc.status}
                    </span>
                  </div>

                  <h4 className="text-xs font-semibold text-slate-200 line-clamp-1">
                    {inc.title}
                  </h4>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-slate-800/60 text-[10px] font-mono text-slate-400">
                    <span>{inc.assigned_to}</span>
                    <span>{new Date(inc.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Selected Incident Detail Pane */}
        <div className="lg:col-span-7 cyber-panel rounded-xl p-6 space-y-6">
          {selectedIncident ? (
            <>
              {/* Incident Header */}
              <div className="pb-5 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2.5 mb-1.5">
                    <span className="text-lg font-mono font-bold text-cyan-300">
                      INCIDENT #{selectedIncident.incident_code}
                    </span>
                    <SeverityBadge severity={selectedIncident.severity} size="md" />
                    <MitreBadge technique={selectedIncident.mitre_technique} />
                  </div>
                  <h2 className="text-sm font-bold text-white">
                    {selectedIncident.title}
                  </h2>
                </div>

                <div className="text-right shrink-0">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Containment Status</div>
                  <div className={`text-sm font-mono font-bold uppercase tracking-wider ${
                    selectedIncident.status === 'CONTAINED' ? 'text-emerald-400' : 'text-red-400'
                  }`}>
                    {selectedIncident.status}
                  </div>
                </div>
              </div>

              {/* Description */}
              <div className="p-3.5 rounded-lg bg-slate-900/80 border border-slate-800 text-xs font-mono text-slate-300 leading-relaxed">
                {selectedIncident.description}
              </div>

              {/* Attack Vector Timeline */}
              <div>
                <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 mb-3 flex items-center gap-2">
                  <Clock className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Attack Reconstruction Timeline</span>
                </h4>
                <div className="space-y-2 font-mono text-xs">
                  {sampleTimeline.map((item, idx) => (
                    <div key={idx} className="flex items-start gap-3 p-2.5 rounded bg-slate-900/50 border border-slate-800/80">
                      <span className="text-slate-500 shrink-0 text-[11px]">{item.time}</span>
                      <div className="flex-1">
                        <div className={`font-semibold ${item.status === 'critical' ? 'text-red-400' : (item.status === 'warn' ? 'text-amber-400' : 'text-slate-300')}`}>
                          {item.event}
                        </div>
                        <div className="text-[10px] text-slate-500 mt-0.5">{item.source}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Interactive Containment Triggers */}
              <div className="pt-4 border-t border-slate-800">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300">
                    Recommended Containment Playbooks
                  </h4>
                  <span className="text-[10px] font-mono text-cyan-400">Zero In-line Outage Risk</span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-xs">
                  <button
                    onClick={() => handleAction('revoke_session')}
                    disabled={executing}
                    className="p-3 rounded-lg bg-red-600/20 hover:bg-red-600/30 border border-red-500/40 text-red-300 font-semibold text-center transition-all flex flex-col items-center gap-1.5"
                  >
                    <UserX className="w-4 h-4" />
                    <span>Revoke Session</span>
                  </button>

                  <button
                    onClick={() => handleAction('block_ip')}
                    disabled={executing}
                    className="p-3 rounded-lg bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/40 text-purple-300 font-semibold text-center transition-all flex flex-col items-center gap-1.5"
                  >
                    <Ban className="w-4 h-4" />
                    <span>Block Attacker IP</span>
                  </button>

                  <button
                    onClick={() => handleAction('require_mfa')}
                    disabled={executing}
                    className="p-3 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 border border-amber-500/40 text-amber-300 font-semibold text-center transition-all flex flex-col items-center gap-1.5"
                  >
                    <Smartphone className="w-4 h-4" />
                    <span>Require MFA</span>
                  </button>

                  <button
                    onClick={() => handleAction('block_url')}
                    disabled={executing}
                    className="p-3 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 border border-blue-500/40 text-blue-300 font-semibold text-center transition-all flex flex-col items-center gap-1.5"
                  >
                    <Lock className="w-4 h-4" />
                    <span>Sinkhole URL</span>
                  </button>
                </div>

                {actionLog && (
                  <div className="mt-4 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs font-mono flex items-center gap-2 animate-fadeIn">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>
                      <strong>SIMULATED CONTAINMENT SUCCESSFUL:</strong> {actionLog}
                    </span>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="p-12 text-center text-slate-500 font-mono text-xs">
              Select an incident from the queue to view forensic details and execute containment playbooks.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
