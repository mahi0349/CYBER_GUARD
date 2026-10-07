import React, { useState, useMemo } from 'react';
import {
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
  Laptop,
  Layers,
  Sparkles
} from 'lucide-react';
import {
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
  const [activeTab, setActiveTab] = useState<'powershell' | 'cmd' | 'bash'>('powershell');

  // Compute deployed backend URL from current browser location
  const backendUrl = useMemo(() => {
    if (typeof window !== 'undefined') {
      const origin = window.location.origin;
      // If deployed or local, use origin or port 8000
      if (origin.includes(':5173') || origin.includes(':3000')) {
        return 'http://127.0.0.1:8000';
      }
      return origin;
    }
    return 'http://127.0.0.1:8000';
  }, []);

  if (!isOpen) return null;

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

  const psCommand = backendUrl === 'http://127.0.0.1:8000'
    ? 'python -m agent.main'
    : `$env:QUANTUMVAULT_BACKEND_URL="${backendUrl}"; python -m agent.main`;

  const cmdCommand = backendUrl === 'http://127.0.0.1:8000'
    ? '.\\run_agent.bat'
    : `.\\run_agent.bat ${backendUrl}`;

  const bashCommand = backendUrl === 'http://127.0.0.1:8000'
    ? 'python3 -m agent.main'
    : `QUANTUMVAULT_BACKEND_URL="${backendUrl}" python3 -m agent.main`;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl bg-[#090d16] border border-cyan-500/40 rounded-2xl shadow-2xl shadow-cyan-950/80 overflow-hidden text-slate-100 ring-1 ring-cyan-500/20 max-h-[90vh] flex flex-col">
        {/* Top Glow accent */}
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent"></div>

        {/* Header */}
        <div className="p-6 border-b border-slate-800/80 flex items-center justify-between shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shadow-md shadow-cyan-950/60">
              <Terminal className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold font-mono tracking-tight text-white">
                  START AGENT IN TERMINAL
                </h2>
                <span className="flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/15 border border-amber-500/40 text-amber-300">
                  <Lock className="w-3 h-3" />
                  SINGLE-DEVICE MODE
                </span>
              </div>
              <p className="text-xs font-mono text-slate-400 mt-0.5">
                Execute the local agent in your terminal to start streaming real-time security telemetry
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
                    Currently streaming live telemetry. QuantumVault enforces 1 active machine at a time.
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
                  No machine is currently locked. Run the command below in your local terminal to connect.
                </p>
              </div>
            </div>
          )}

          {/* Terminal Tabs */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span>TERMINAL COMMAND</span>
              </span>

              {/* Tab Selector */}
              <div className="flex items-center p-1 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono">
                <button
                  onClick={() => setActiveTab('powershell')}
                  className={`px-3 py-1 rounded font-bold transition-all ${
                    activeTab === 'powershell'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  PowerShell
                </button>
                <button
                  onClick={() => setActiveTab('cmd')}
                  className={`px-3 py-1 rounded font-bold transition-all ${
                    activeTab === 'cmd'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Batch (.bat)
                </button>
                <button
                  onClick={() => setActiveTab('bash')}
                  className={`px-3 py-1 rounded font-bold transition-all ${
                    activeTab === 'bash'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Bash / Linux
                </button>
              </div>
            </div>

            {/* Terminal Snippet Box */}
            <div className="relative group rounded-xl bg-slate-950 border border-slate-800/90 hover:border-cyan-500/50 p-4 transition-all shadow-inner">
              <div className="flex items-center justify-between gap-4">
                <code className="text-xs font-mono text-cyan-300 break-all select-all leading-relaxed">
                  {activeTab === 'powershell' && psCommand}
                  {activeTab === 'cmd' && cmdCommand}
                  {activeTab === 'bash' && bashCommand}
                </code>

                <button
                  onClick={() => {
                    const text = activeTab === 'powershell' ? psCommand : activeTab === 'cmd' ? cmdCommand : bashCommand;
                    handleCopy(text, 'terminal_cmd');
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono font-bold text-slate-200 transition-all border border-slate-700 shrink-0"
                >
                  {copiedCmd === 'terminal_cmd' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Step-by-Step Instructions */}
          <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-3 font-mono text-xs">
            <span className="text-[11px] uppercase tracking-wider text-slate-400 font-bold block mb-1">
              ⚡ How to Run on Your PC:
            </span>
            <div className="flex items-start gap-2.5 text-slate-300">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cyan-500/20 text-cyan-400 font-bold text-[10px]">
                1
              </span>
              <span>
                Open <strong className="text-white">PowerShell</strong> or <strong className="text-white">Command Prompt</strong> as <strong className="text-emerald-400">Administrator</strong> (required for Windows Defender, Firewall, and deep process telemetry inspection).
              </span>
            </div>
            <div className="flex items-start gap-2.5 text-slate-300">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cyan-500/20 text-cyan-400 font-bold text-[10px]">
                2
              </span>
              <span>
                Navigate to your project directory: <code className="text-cyan-300 bg-slate-900 px-1.5 py-0.5 rounded">cd "d:\BPUT Project"</code>
              </span>
            </div>
            <div className="flex items-start gap-2.5 text-slate-300">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cyan-500/20 text-cyan-400 font-bold text-[10px]">
                3
              </span>
              <span>
                Paste and run the command above. The agent immediately binds this single machine to the Command Center and turns the dashboard to <strong className="text-emerald-400">AGENT ONLINE</strong>.
              </span>
            </div>
          </div>

          {/* Single-Device Policy Reminder */}
          <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-start gap-2.5 text-amber-200/90 text-xs font-mono">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <p>
              <strong>Single-Device Enforcement:</strong> Only 1 computer can run the agent at a time. If you switch to another machine, click <em>"Release Device Lock"</em> or stop the agent on this machine first.
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
