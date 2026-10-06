import React from 'react';
import { X, ShieldAlert, Cpu, HardDrive, Terminal, Network, User, Clock } from 'lucide-react';
import { ProcessItem, NetworkItem } from '../../types/commandCenter';

interface ProcessModalProps {
  process: ProcessItem | null;
  networkConns: NetworkItem[];
  onClose: () => void;
}

export const ProcessModal: React.FC<ProcessModalProps> = ({ process, networkConns, onClose }) => {
  if (!process) return null;

  const relatedConns = networkConns.filter(c => c.pid === process.pid);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-[#0b101d] border border-cyan-500/40 rounded-xl w-full max-w-3xl overflow-hidden shadow-2xl shadow-cyan-950/50 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white font-mono">{process.name}</h3>
                <span className="text-xs px-2 py-0.5 rounded font-mono bg-slate-800 text-slate-300 border border-slate-700">
                  PID: {process.pid}
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${
                  process.risk_level === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border-red-500/40' :
                  process.risk_level === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border-orange-500/40' :
                  process.risk_level === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400 border-amber-500/40' :
                  'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                }`}>
                  {process.risk_level} RISK ({process.risk_score}/100)
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5 truncate max-w-xl">
                {process.exe_path || 'Executable path restricted or system process'}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-6 text-sm">
          {/* Quick Metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-[11px] text-slate-400 font-mono block">CPU Usage</span>
              <span className="text-base font-bold text-cyan-400 font-mono">{process.cpu_percent}%</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-[11px] text-slate-400 font-mono block">Memory (RSS)</span>
              <span className="text-base font-bold text-emerald-400 font-mono">{process.memory_mb} MB</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-[11px] text-slate-400 font-mono block">User Context</span>
              <span className="text-xs font-mono text-slate-200 truncate block mt-0.5">{process.username || 'SYSTEM'}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-[11px] text-slate-400 font-mono block">Parent PID</span>
              <span className="text-base font-bold text-slate-200 font-mono">{process.ppid ?? 'N/A'}</span>
            </div>
          </div>

          {/* Risk Factors / Anomalies */}
          {process.risk_reasons && process.risk_reasons.length > 0 ? (
            <div className="p-4 rounded-lg bg-amber-500/10 border border-amber-500/30">
              <div className="flex items-center gap-2 text-amber-400 font-mono text-xs font-bold mb-2">
                <ShieldAlert className="w-4 h-4" />
                <span>OBSERVED RISK ANOMALIES</span>
              </div>
              <ul className="space-y-1 text-xs font-mono text-amber-200/90 list-disc list-inside">
                {process.risk_reasons.map((r, idx) => (
                  <li key={idx}>{r}</li>
                ))}
              </ul>
            </div>
          ) : (
            <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono flex items-center gap-2">
              <span>Standard system execution path. No anomalous flags identified.</span>
            </div>
          )}

          {/* Command Line Execution Details */}
          <div>
            <h4 className="text-xs font-mono uppercase text-slate-400 font-bold mb-2">Command Line Argument</h4>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 break-all select-all">
              {process.cmdline || process.exe_path || 'No command line parameters available'}
            </div>
          </div>

          {/* Correlated Active Network Connections */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-xs font-mono uppercase text-slate-400 font-bold flex items-center gap-2">
                <Network className="w-3.5 h-3.5 text-cyan-400" />
                <span>Correlated Network Connections ({relatedConns.length})</span>
              </h4>
            </div>

            {relatedConns.length === 0 ? (
              <p className="text-xs font-mono text-slate-500 p-3 rounded-lg bg-slate-900/50 border border-slate-800/80">
                No active TCP/UDP sockets mapped to PID {process.pid}.
              </p>
            ) : (
              <div className="border border-slate-800 rounded-lg overflow-hidden">
                <table className="w-full text-xs font-mono text-left">
                  <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="px-3 py-2">Proto</th>
                      <th className="px-3 py-2">Local Address</th>
                      <th className="px-3 py-2">Remote Address</th>
                      <th className="px-3 py-2">State</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {relatedConns.map((c, i) => (
                      <tr key={i} className="hover:bg-slate-900/40">
                        <td className="px-3 py-2 text-cyan-400 font-semibold">{c.protocol}</td>
                        <td className="px-3 py-2 text-slate-300">{c.local_ip}:{c.local_port}</td>
                        <td className="px-3 py-2 text-slate-300">{c.remote_ip}:{c.remote_port}</td>
                        <td className="px-3 py-2">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                            c.state === 'ESTABLISHED' ? 'bg-emerald-500/20 text-emerald-300' :
                            c.state === 'LISTEN' ? 'bg-blue-500/20 text-blue-300' :
                            'bg-slate-800 text-slate-400'
                          }`}>
                            {c.state}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-900/80 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
