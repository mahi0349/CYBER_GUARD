import React, { useState } from 'react';
import {
  Download,
  Terminal,
  Shield,
  CheckCircle2,
  Lock,
  Copy,
  Check,
  X,
  FileCode2,
  AlertTriangle,
  Play,
  Cpu,
  Laptop
} from 'lucide-react';
import {
  getAgentDownloadUrl,
  getAgentScriptDownloadUrl,
  disconnectDevice,
  DeviceModeInfo
} from '../../services/commandCenterApi';

interface AgentDownloadModalProps {
  isOpen: boolean;
  onClose: () => void;
  activeDeviceName?: string | null;
  activeDeviceId?: string | null;
  deviceModeInfo?: DeviceModeInfo | null;
  onDeviceDisconnected?: () => void;
}

export const AgentDownloadModal: React.FC<AgentDownloadModalProps> = ({
  isOpen,
  onClose,
  activeDeviceName,
  activeDeviceId,
  deviceModeInfo,
  onDeviceDisconnected
}) => {
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [isDisconnecting, setIsDisconnecting] = useState(false);

  if (!isOpen) return null;

  const exeDownloadUrl = getAgentDownloadUrl();
  const scriptDownloadUrl = getAgentScriptDownloadUrl();

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const handleDisconnect = async () => {
    setIsDisconnecting(true);
    try {
      await disconnectDevice();
      if (onDeviceDisconnected) onDeviceDisconnected();
    } finally {
      setIsDisconnecting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl bg-[#090d16] border border-cyan-500/40 rounded-2xl shadow-2xl shadow-cyan-950/80 overflow-hidden text-slate-100 ring-1 ring-cyan-500/20 max-h-[90vh] flex flex-col">
        {/* Glow accent */}
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent"></div>

        {/* Header */}
        <div className="p-6 border-b border-slate-800/80 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-md shadow-cyan-950/60">
              <Download className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold font-mono tracking-tight text-white">
                  DOWNLOAD QUANTUMVAULT AGENT
                </h2>
                <span className="flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/15 border border-amber-500/40 text-amber-300">
                  <Lock className="w-3 h-3" />
                  SINGLE-DEVICE MODE
                </span>
              </div>
              <p className="text-xs font-mono text-slate-400 mt-0.5">
                Download and run the local endpoint agent on your PC (1 device active at a time)
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800/80 transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body content */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* Active Device Lock Status Banner */}
          {activeDeviceId ? (
            <div className="p-4 rounded-xl bg-slate-900/90 border border-cyan-500/30 flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                  <Laptop className="w-5 h-5" />
                </div>
                <div>
                  <div className="text-xs font-mono font-bold text-white flex items-center gap-2">
                    <span>ACTIVE PAIRED DEVICE:</span>
                    <span className="text-cyan-300 font-mono">{activeDeviceName || activeDeviceId}</span>
                  </div>
                  <p className="text-[11px] font-mono text-slate-400 mt-0.5">
                    Currently streaming live telemetry. QuantumVault enforces 1 active device at a time.
                  </p>
                </div>
              </div>
              <button
                onClick={handleDisconnect}
                disabled={isDisconnecting}
                className="px-3 py-1.5 rounded-lg bg-red-500/15 hover:bg-red-500/25 border border-red-500/40 text-red-300 text-xs font-mono font-bold transition-all shrink-0"
                title="Disconnect this device so you can bind another machine"
              >
                {isDisconnecting ? 'Disconnecting...' : 'Release Device Lock'}
              </button>
            </div>
          ) : (
            <div className="p-4 rounded-xl bg-slate-900/90 border border-cyan-500/20 flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                <Cpu className="w-5 h-5" />
              </div>
              <div>
                <div className="text-xs font-mono font-bold text-white">READY FOR AGENT CONNECTION</div>
                <p className="text-[11px] font-mono text-slate-400 mt-0.5">
                  No active machine is locked. Run the agent locally to stream telemetry immediately.
                </p>
              </div>
            </div>
          )}

          {/* Download Options */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Option 1: Standalone .EXE */}
            <div className="p-5 rounded-xl bg-gradient-to-b from-slate-900 via-slate-900/90 to-slate-950 border border-cyan-500/40 shadow-lg shadow-cyan-950/40 relative group hover:border-cyan-400 transition-all flex flex-col justify-between">
              <div className="absolute top-2.5 right-2.5 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/20 border border-cyan-400/40 text-cyan-300">
                RECOMMENDED
              </div>
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-mono font-bold text-white">QuantumVault-Agent.exe</h3>
                </div>
                <p className="text-xs font-mono text-slate-400 mb-4 leading-relaxed">
                  Standalone compiled Windows executable. No Python installation needed. Double-click to run.
                </p>
              </div>
              <a
                href={exeDownloadUrl}
                download="QuantumVault-Agent.exe"
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl bg-gradient-to-r from-cyan-600 via-blue-600 to-cyan-500 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-md shadow-cyan-500/20 transition-all border border-cyan-400/40"
              >
                <Download className="w-4 h-4" />
                <span>DOWNLOAD .EXE (36 MB)</span>
              </a>
            </div>

            {/* Option 2: 1-Click Batch Launcher */}
            <div className="p-5 rounded-xl bg-gradient-to-b from-slate-900 via-slate-900/90 to-slate-950 border border-slate-800 hover:border-cyan-500/40 transition-all flex flex-col justify-between">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <FileCode2 className="w-4 h-4 text-blue-400" />
                  <h3 className="text-sm font-mono font-bold text-white">run_agent.bat</h3>
                </div>
                <p className="text-xs font-mono text-slate-400 mb-4 leading-relaxed">
                  Lightweight Windows launcher script. Auto-detects local executable or Python environment.
                </p>
              </div>
              <a
                href={scriptDownloadUrl}
                download="run_quantumvault_agent.bat"
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs font-bold transition-all border border-slate-700 hover:border-cyan-500/40"
              >
                <Download className="w-4 h-4" />
                <span>DOWNLOAD RUNNER (.BAT)</span>
              </a>
            </div>
          </div>

          {/* Quick Terminal Command */}
          <div className="space-y-2">
            <span className="text-xs font-mono uppercase text-slate-400 font-bold flex items-center gap-1.5">
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              <span>Or Run from Project Directory:</span>
            </span>
            <div className="flex items-center justify-between p-3 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-cyan-300">
              <code>.\dist\QuantumVault-Agent.exe</code>
              <button
                onClick={() => handleCopy('.\\dist\\QuantumVault-Agent.exe', 'cmd1')}
                className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-all"
                title="Copy command"
              >
                {copiedCmd === 'cmd1' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Instructions checklist */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-3 font-mono text-xs">
            <span className="text-[11px] uppercase tracking-wider text-slate-400 font-bold block mb-1">
              ⚡ How to Run on Your PC:
            </span>
            <div className="flex items-start gap-2.5 text-slate-300">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cyan-500/20 text-cyan-400 font-bold text-[10px]">
                1
              </span>
              <span>
                Download <strong className="text-white">QuantumVault-Agent.exe</strong> to your computer.
              </span>
            </div>
            <div className="flex items-start gap-2.5 text-slate-300">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cyan-500/20 text-cyan-400 font-bold text-[10px]">
                2
              </span>
              <span>
                Right-click the executable and select <strong className="text-emerald-400">"Run as administrator"</strong> to enable Defender, Firewall, and deep process telemetry inspection.
              </span>
            </div>
            <div className="flex items-start gap-2.5 text-slate-300">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cyan-500/20 text-cyan-400 font-bold text-[10px]">
                3
              </span>
              <span>
                The agent will immediately lock this single machine and pipe real-time security telemetry directly into this Command Center.
              </span>
            </div>
          </div>

          {/* Single-Device Policy Rule Reminder */}
          <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-start gap-2.5 text-amber-200/90 text-xs font-mono">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <p>
              <strong>Single-Device Rule:</strong> Only 1 device may run the agent at any given time. If another computer attempts to connect while a device is active, it will be automatically blocked to prevent cross-device contamination.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800/80 bg-slate-950/60 flex items-center justify-end shrink-0">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-mono text-xs font-bold transition-all border border-slate-700"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
