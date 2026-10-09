import React, { useState } from 'react';
import { X, Play, RefreshCw, CheckCircle2, AlertTriangle, ShieldCheck, Cpu, FolderGit2, Globe, FileCode2, Wrench, Zap } from 'lucide-react';
import { ScanRecord } from '../../types/commandCenter';
import { triggerScan, triggerAllScans } from '../../services/commandCenterApi';

interface ScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  scans: ScanRecord[];
  onScanTriggered: (scan: ScanRecord) => void;
  isAgentOnline: boolean;
  deviceId?: string;
  isScanningAll?: boolean;
  onTriggerAll?: () => Promise<void>;
}

export const ScanModal: React.FC<ScanModalProps> = ({
  isOpen,
  onClose,
  scans,
  onScanTriggered,
  isAgentOnline,
  deviceId,
  isScanningAll = false,
  onTriggerAll
}) => {
  const [loadingType, setLoadingType] = useState<string | null>(null);
  const [localScanningAll, setLocalScanningAll] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const isAllRunning = isScanningAll || localScanningAll;

  const scanOptions = [
    {
      id: 'quick',
      name: 'Quick Security Scan',
      desc: 'Validates active Defender real-time protection, Firewall status, and high-risk processes.',
      icon: ShieldCheck,
      color: 'cyan'
    },
    {
      id: 'process',
      name: 'Process Security Scan',
      desc: 'Analyzes running memory trees, non-standard execution paths, and masquerading binaries.',
      icon: Cpu,
      color: 'blue'
    },
    {
      id: 'startup',
      name: 'Startup Persistence Scan',
      desc: 'Deep audit of Windows Registry Run/RunOnce keys and User/System startup folders.',
      icon: FolderGit2,
      color: 'amber'
    },
    {
      id: 'network',
      name: 'Network & Port Scan',
      desc: 'Inspects listening local ports, anomalous outbound targets, and socket PID correlations.',
      icon: Globe,
      color: 'purple'
    },
    {
      id: 'file',
      name: 'Monitored File Integrity Scan',
      desc: 'Calculates SHA-256 hashes and inspects new executables in Downloads and Temp directories.',
      icon: FileCode2,
      color: 'emerald'
    },
    {
      id: 'config',
      name: 'Security Configuration Scan',
      desc: 'Audits Windows Defender signatures, definition staleness, and Firewall active profiles.',
      icon: Wrench,
      color: 'orange'
    }
  ];

  const handleLaunchScan = async (scanType: string) => {
    setErrorMsg(null);
    setLoadingType(scanType);
    try {
      const res = await triggerScan(scanType, deviceId);
      onScanTriggered(res);
      if (res.status === 'UNAVAILABLE') {
        setErrorMsg('Scan unavailable: Endpoint agent is disconnected.');
      }
    } catch (e: any) {
      setErrorMsg(e?.response?.data?.detail || e.message || 'Failed to trigger scan.');
    } finally {
      setLoadingType(null);
    }
  };

  const handleLaunchAllScans = async () => {
    setErrorMsg(null);
    setLocalScanningAll(true);
    try {
      if (onTriggerAll) {
        await onTriggerAll();
      } else {
        const results = await triggerAllScans(deviceId);
        results.forEach(r => onScanTriggered(r));
        if (results.some(r => r.status === 'UNAVAILABLE')) {
          setErrorMsg('Scan unavailable: Endpoint agent is disconnected.');
        }
      }
    } catch (e: any) {
      setErrorMsg(e?.response?.data?.detail || e.message || 'Failed to trigger simultaneous scans.');
    } finally {
      setLocalScanningAll(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-[#0b101d] border border-cyan-500/40 rounded-xl w-full max-w-4xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Play className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white font-mono">ENDPOINT SCAN CONSOLE</h3>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Execute genuine diagnostic and security scans on the local Windows endpoint
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
        <div className="p-6 overflow-y-auto space-y-6">
          {!isAgentOnline && (
            <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center gap-3 text-red-300 text-xs font-mono">
              <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
              <div>
                <span className="font-bold">AGENT OFFLINE:</span> Real endpoint scans require an active connected Windows telemetry agent.
              </div>
            </div>
          )}

          {errorMsg && (
            <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono">
              {errorMsg}
            </div>
          )}

          {/* Quick Scan All Banner & Action */}
          <div className="p-4 rounded-xl bg-gradient-to-r from-cyan-950/60 via-slate-900/90 to-blue-950/60 border border-cyan-500/40 shadow-xl shadow-cyan-950/40 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-start sm:items-center gap-3">
              <div className="p-2.5 rounded-xl bg-cyan-500/15 border border-cyan-400/40 text-cyan-300 shadow-md">
                <Zap className="w-5 h-5 text-cyan-400 drop-shadow-[0_0_6px_rgba(34,211,238,0.5)]" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-sm font-bold font-mono text-white tracking-wide">QUICK SCAN — ALL VECTORS</span>
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-400/40">
                    SIMULTANEOUS
                  </span>
                </div>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Execute all 6 diagnostic scans in parallel across processes, network, persistence, files, and Defender config.
                </p>
              </div>
            </div>

            <button
              onClick={handleLaunchAllScans}
              disabled={isAllRunning || !isAgentOnline}
              className={`flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl font-mono text-xs font-bold transition-all shrink-0 ${
                !isAgentOnline
                  ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                  : isAllRunning
                  ? 'bg-cyan-900/70 text-cyan-200 border border-cyan-400/60 shadow-lg shadow-cyan-950/60 cursor-wait'
                  : 'bg-gradient-to-r from-cyan-600 via-blue-600 to-cyan-500 hover:from-cyan-500 hover:to-blue-500 text-white border border-cyan-400/50 shadow-lg shadow-cyan-500/25 hover:shadow-cyan-500/40 active:scale-95'
              }`}
            >
              {isAllRunning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-cyan-300" />
                  <span>EXECUTING ALL SCANS (6/6)...</span>
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 text-cyan-200" />
                  <span>RUN ALL SIMULTANEOUSLY</span>
                </>
              )}
            </button>
          </div>

          {/* Grid of Scanners */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold">
                Available Endpoint Scanners
              </h4>
              {isAllRunning && (
                <div className="flex items-center gap-1.5 text-[11px] font-mono text-cyan-300 animate-pulse">
                  <RefreshCw className="w-3 h-3 animate-spin" />
                  <span>Running all 6 scans in parallel...</span>
                </div>
              )}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {scanOptions.map(opt => {
                const Icon = opt.icon;
                const isRunning = loadingType === opt.id || isAllRunning;
                return (
                  <div
                    key={opt.id}
                    className={`p-4 rounded-xl bg-slate-900/60 border transition-all flex flex-col justify-between ${
                      isRunning ? 'border-cyan-500/60 bg-cyan-950/20' : 'border-slate-800 hover:border-cyan-500/30'
                    }`}
                  >
                    <div>
                      <div className="flex items-center gap-2.5 mb-2">
                        <div className={`p-1.5 rounded-lg border ${
                          isRunning ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50' : 'bg-slate-800 text-cyan-400 border-slate-700'
                        }`}>
                          <Icon className="w-4 h-4" />
                        </div>
                        <span className="text-sm font-bold text-slate-200 font-mono">{opt.name}</span>
                      </div>
                      <p className="text-xs text-slate-400 leading-relaxed mb-4">
                        {opt.desc}
                      </p>
                    </div>

                    <div className="flex justify-end">
                      <button
                        onClick={() => handleLaunchScan(opt.id)}
                        disabled={isRunning || !isAgentOnline}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                          !isAgentOnline
                            ? 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
                            : isRunning
                            ? 'bg-cyan-900/50 text-cyan-300 border border-cyan-500/50'
                            : 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-md shadow-cyan-950'
                        }`}
                      >
                        {isRunning ? (
                          <>
                            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                            <span>SCANNING...</span>
                          </>
                        ) : (
                          <>
                            <Play className="w-3.5 h-3.5" />
                            <span>EXECUTE SCAN</span>
                          </>
                        )}
                      </button>
                    </div>

                  </div>
                );
              })}
            </div>
          </div>

          {/* Scan Execution History */}
          <div>
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold mb-3">
              Recent Scan Activity
            </h4>
            {scans.length === 0 ? (
              <p className="text-xs font-mono text-slate-500 p-4 rounded-lg bg-slate-900/40 border border-slate-800">
                No scans executed yet in this session. Click &quot;Execute Scan&quot; above to run a scan.
              </p>
            ) : (
              <div className="border border-slate-800 rounded-lg overflow-hidden">
                <table className="w-full text-xs font-mono text-left">
                  <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="px-3 py-2">Scan ID</th>
                      <th className="px-3 py-2">Target</th>
                      <th className="px-3 py-2">Status</th>
                      <th className="px-3 py-2">Findings</th>
                      <th className="px-3 py-2">Started</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {scans.slice(0, 8).map(s => (
                      <tr key={s.scan_id} className="hover:bg-slate-900/30">
                        <td className="px-3 py-2 text-slate-300">{s.scan_id}</td>
                        <td className="px-3 py-2 text-cyan-400 uppercase font-bold">{s.scan_type}</td>
                        <td className="px-3 py-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            s.status === 'COMPLETED' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                            s.status === 'RUNNING' ? 'bg-cyan-500/20 text-cyan-400 animate-pulse border border-cyan-500/30' :
                            s.status === 'QUEUED' ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' :
                            'bg-red-500/20 text-red-400 border border-red-500/30'
                          }`}>
                            {s.status}
                          </span>
                        </td>
                        <td className="px-3 py-2 font-bold text-slate-200">
                          {s.findings_count} {s.findings_count === 1 ? 'anomaly' : 'anomalies'}
                        </td>
                        <td className="px-3 py-2 text-slate-400">
                          {new Date(s.started_at).toLocaleTimeString()}
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
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
