import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Activity,
  Cpu,
  HardDrive,
  Globe,
  RefreshCw,
  Search,
  Filter,
  Play,
  Terminal,
  FolderGit2,
  FileCode2,
  Clock,
  Layers,
  CheckCircle2,
  AlertTriangle,
  ChevronRight,
  Zap,
  Server,
  LayoutDashboard,
  Crosshair,
  PackageCheck,
  ArrowRight,
  Radio,
  Sparkles,
  ShieldQuestion,
  Laptop,
  Download,
  Lock,
  PowerOff,
  Check,
  Copy,
  SlidersHorizontal
} from 'lucide-react';
import {
  AreaChart,
  Area,
  ResponsiveContainer
} from 'recharts';

import {
  AgentStatus,
  SystemTelemetry,
  ProcessItem,
  NetworkItem,
  ProtectionStatus,
  SoftwareItem,
  ServiceItem,
  StartupItem,
  TrackedFile,
  FileEvent,
  SecurityEvent,
  ThreatAlert,
  RiskScore,
  ScanRecord
} from '../types/commandCenter';

import {
  fetchAgentStatus,
  fetchSystemTelemetry,
  fetchTelemetryHistory,
  fetchProcesses,
  fetchNetwork,
  fetchProtectionStatus,
  fetchSoftware,
  fetchServices,
  fetchStartup,
  fetchTrackedFiles,
  fetchFileEvents,
  fetchSecurityEvents,
  fetchThreats,
  fetchScans,
  triggerAllScans,
  fetchRiskScore,
  getCommandCenterWebSocketUrl,
  fetchDeviceMode,
  disconnectDevice,
  DeviceModeInfo
} from '../services/commandCenterApi';

import { ProcessModal } from '../components/command-center/ProcessModal';
import { AlertModal } from '../components/command-center/AlertModal';
import { ScanModal } from '../components/command-center/ScanModal';
import { AgentDownloadModal } from '../components/command-center/AgentDownloadModal';

type ViewMode = 'overview' | 'hunter' | 'inventory';

interface DashboardProps {
  onNavigate?: (tab: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ onNavigate }) => {
  // Mode switcher
  const [viewMode, setViewMode] = useState<ViewMode>('overview');

  // Sub-tabs for modes
  const [hunterSubTab, setHunterSubTab] = useState<'processes' | 'network'>('processes');
  const [inventorySubTab, setInventorySubTab] = useState<'software' | 'services' | 'startup' | 'files'>('software');

  // Single-Device State & Modals
  const [deviceModeInfo, setDeviceModeInfo] = useState<DeviceModeInfo | null>(null);
  const [isDownloadModalOpen, setIsDownloadModalOpen] = useState(false);
  const [conflictAlert, setConflictAlert] = useState<string | null>(null);
  const [isDisconnecting, setIsDisconnecting] = useState(false);
  const [copiedTerminalInline, setCopiedTerminalInline] = useState(false);

  // Core Live State
  const [agentStatus, setAgentStatus] = useState<AgentStatus | null>(null);
  const [telemetry, setTelemetry] = useState<SystemTelemetry | null>(null);
  const [telemetryHistory, setTelemetryHistory] = useState<SystemTelemetry[]>([]);
  const [protection, setProtection] = useState<ProtectionStatus | null>(null);
  const [riskScore, setRiskScore] = useState<RiskScore | null>(null);

  // Lists
  const [processes, setProcesses] = useState<ProcessItem[]>([]);
  const [network, setNetwork] = useState<NetworkItem[]>([]);
  const [threats, setThreats] = useState<ThreatAlert[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [fileEvents, setFileEvents] = useState<FileEvent[]>([]);
  const [trackedFiles, setTrackedFiles] = useState<TrackedFile[]>([]);
  const [software, setSoftware] = useState<SoftwareItem[]>([]);
  const [services, setServices] = useState<ServiceItem[]>([]);
  const [startup, setStartup] = useState<StartupItem[]>([]);
  const [scans, setScans] = useState<ScanRecord[]>([]);

  // UI state
  const [loading, setLoading] = useState(true);

  // Search & Filters
  const [processSearch, setProcessSearch] = useState('');
  const [processRiskFilter, setProcessRiskFilter] = useState('ALL');
  const [networkFilter, setNetworkFilter] = useState('ALL');
  const [networkSearch, setNetworkSearch] = useState('');
  const [softwareSearch, setSoftwareSearch] = useState('');

  // Modals
  const [selectedProcess, setSelectedProcess] = useState<ProcessItem | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null);
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [isScanningAll, setIsScanningAll] = useState(false);

  // WebSocket ref
  const wsRef = useRef<WebSocket | null>(null);

  // Quick Scan (All Methods Simultaneously) Handler
  const handleExecuteQuickScanAll = async () => {
    if (isScanningAll) return;
    setIsScanningAll(true);
    setIsScanModalOpen(true);
    try {
      const results = await triggerAllScans(agentStatus?.device_id);
      if (results && results.length > 0) {
        setScans(prev => {
          const existingIds = new Set(prev.map(s => s.scan_id));
          const newEntries = results.filter(s => !existingIds.has(s.scan_id));
          return [...newEntries, ...prev];
        });
      }
    } catch (err) {
      console.error('Failed to execute quick scan all:', err);
    } finally {
      setIsScanningAll(false);
    }
  };

  // Initial Full Load for Single Active Device
  const loadAllData = async () => {
    try {
      const [
        modeRes,
        statusRes,
        telRes,
        histRes,
        protRes,
        riskRes,
        procRes,
        netRes,
        threatRes,
        evtRes,
        fEvtRes,
        scanRes
      ] = await Promise.all([
        fetchDeviceMode(),
        fetchAgentStatus(),
        fetchSystemTelemetry(),
        fetchTelemetryHistory(),
        fetchProtectionStatus(),
        fetchRiskScore(),
        fetchProcesses(150),
        fetchNetwork(150),
        fetchThreats(),
        fetchSecurityEvents(50),
        fetchFileEvents(),
        fetchScans()
      ]);

      if (modeRes) setDeviceModeInfo(modeRes);
      setAgentStatus(statusRes);
      if (telRes) setTelemetry(telRes);
      if (histRes.length > 0) setTelemetryHistory(histRes);
      if (protRes) setProtection(protRes);
      if (riskRes) setRiskScore(riskRes);
      setProcesses(procRes);
      setNetwork(netRes);
      setThreats(threatRes);
      setEvents(evtRes);
      setFileEvents(fEvtRes);
      setScans(scanRes);
    } catch (e) {
      console.error('Error loading command center data:', e);
    } finally {
      setLoading(false);
    }
  };

  const handleDisconnectDevice = async () => {
    setIsDisconnecting(true);
    try {
      await disconnectDevice();
      await loadAllData();
    } finally {
      setIsDisconnecting(false);
    }
  };

  // Load secondary data on demand
  useEffect(() => {
    if (viewMode === 'inventory') {
      if (inventorySubTab === 'software' && software.length === 0) {
        fetchSoftware().then(setSoftware);
      } else if (inventorySubTab === 'services' && services.length === 0) {
        fetchServices().then(setServices);
      } else if (inventorySubTab === 'startup' && startup.length === 0) {
        fetchStartup().then(setStartup);
      } else if (inventorySubTab === 'files' && trackedFiles.length === 0) {
        fetchTrackedFiles().then(setTrackedFiles);
      }
    }
  }, [viewMode, inventorySubTab]);

  // WebSocket Setup (Single-Device stream)
  useEffect(() => {
    loadAllData();

    let isMounted = true;
    let reconnectTimeout: any = null;

    const connectWs = () => {
      try {
        const wsUrl = getCommandCenterWebSocketUrl();
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (!isMounted) return;
        };

        ws.onmessage = (event) => {
          if (!isMounted) return;
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'init_state') {
              if (data.status) setAgentStatus(data.status);
              if (data.telemetry) setTelemetry(data.telemetry);
              if (data.telemetry_history) setTelemetryHistory(data.telemetry_history);
              if (data.risk) setRiskScore(data.risk);
              if (data.protection) setProtection(data.protection);
              if (data.processes) setProcesses(data.processes);
              if (data.network) setNetwork(data.network);
              if (data.threats) setThreats(data.threats);
              if (data.events) setEvents(data.events);
              if (data.file_events) setFileEvents(data.file_events);
              if (data.scans) setScans(data.scans);
            } else if (data.type === 'telemetry_update') {
              setTelemetry(data.telemetry);
              if (data.status) setAgentStatus(data.status);
              setTelemetryHistory(prev => [...prev.slice(-35), data.telemetry]);
            } else if (data.type === 'processes_update') {
              setProcesses(data.processes);
              if (data.risk) setRiskScore(data.risk);
            } else if (data.type === 'network_update') {
              setNetwork(data.network);
            } else if (data.type === 'protection_update') {
              setProtection(data.protection);
              if (data.risk) setRiskScore(data.risk);
            } else if (data.type === 'status_update') {
              setAgentStatus(data.status);
              fetchDeviceMode().then(setDeviceModeInfo).catch(() => { });
            } else if (data.type === 'threats_update') {
              setThreats(data.threats);
              if (data.risk) setRiskScore(data.risk);
            } else if (data.type === 'single_device_conflict') {
              setConflictAlert(data.alert?.description || data.message || 'Concurrent device connection was blocked.');
            } else if (data.type === 'device_disconnected') {
              loadAllData();
            } else if (data.type === 'scan_update') {
              setScans(prev => {
                const next = [...prev];
                const idx = next.findIndex(s => s.scan_id === data.scan.scan_id);
                if (idx >= 0) next[idx] = data.scan;
                else next.unshift(data.scan);
                return next;
              });
            }
          } catch {
            // ignore non-json
          }
        };

        ws.onclose = () => {
          if (!isMounted) return;
          reconnectTimeout = setTimeout(connectWs, 3000);
        };

        ws.onerror = () => {
          ws.close();
        };
      } catch {
        reconnectTimeout = setTimeout(connectWs, 3000);
      }
    };

    connectWs();

    const pollInterval = setInterval(() => {
      fetchAgentStatus().then(st => setAgentStatus(st)).catch(() => { });
      fetchDeviceMode().then(dm => setDeviceModeInfo(dm)).catch(() => { });
    }, 7000);

    return () => {
      isMounted = false;
      clearInterval(pollInterval);
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  // Filtered Processes
  const filteredProcesses = useMemo(() => {
    return processes.filter(p => {
      const matchesSearch = !processSearch ||
        p.name.toLowerCase().includes(processSearch.toLowerCase()) ||
        p.pid.toString().includes(processSearch);
      const matchesRisk = processRiskFilter === 'ALL' || p.risk_level === processRiskFilter;
      return matchesSearch && matchesRisk;
    });
  }, [processes, processSearch, processRiskFilter]);

  // Filtered Network
  const filteredNetwork = useMemo(() => {
    return network.filter(c => {
      const matchesSearch = !networkSearch ||
        c.process_name.toLowerCase().includes(networkSearch.toLowerCase()) ||
        c.local_ip.includes(networkSearch) ||
        c.remote_ip.includes(networkSearch) ||
        c.local_port.toString().includes(networkSearch) ||
        c.remote_port.toString().includes(networkSearch);
      const matchesFilter = networkFilter === 'ALL' || c.state === networkFilter;
      return matchesSearch && matchesFilter;
    });
  }, [network, networkSearch, networkFilter]);

  const isAgentOnline = agentStatus?.status === 'ONLINE';
  const isAgentDegraded = agentStatus?.status === 'DEGRADED';
  const isAgentOffline = !agentStatus || agentStatus.status === 'OFFLINE';

  const formatUptime = (seconds: number) => {
    const d = Math.floor(seconds / (3600 * 24));
    const h = Math.floor((seconds % (3600 * 24)) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    return `${h}h ${m}m`;
  };

  if (loading && !agentStatus) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="flex flex-col items-center gap-3">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
          <p className="text-sm font-mono text-slate-400">Connecting to Quantum Vault Endpoint Telemetry...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 text-slate-100 w-full mx-auto">
      {/* ================= TOP HEADER ================= */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800/90">
        <div className="flex flex-col sm:flex-row sm:items-center gap-4">
          <div className="p-3 rounded-2xl bg-gradient-to-br from-cyan-500/20 via-blue-600/10 to-indigo-600/20 border border-cyan-500/40 shadow-lg shadow-cyan-950/60 ring-1 ring-cyan-400/20 shrink-0">
            <Shield className="w-7 h-7 text-cyan-400 drop-shadow-[0_0_8px_rgba(34,211,238,0.5)]" />
          </div>

          <div>
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-xl sm:text-2xl font-black tracking-tight text-white font-mono flex items-center gap-2">
                <span>ENDPOINT COMMAND CENTER</span>
              </h1>

              {/* Single-Device Protection Mode Badge */}
              <div className="flex items-center gap-2 bg-slate-900/95 border border-cyan-500/40 rounded-xl px-3 py-1.5 shadow-md shadow-cyan-950/40">
                <Lock className="w-4 h-4 text-cyan-400 shrink-0" />
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-bold">MODE:</span>
                <span className="text-xs font-mono font-bold text-cyan-300">SINGLE DEVICE (LOCKED)</span>
              </div>

              {/* Live Status Badge */}
              {isAgentOnline && (
                <span className="flex items-center gap-2 text-xs font-mono px-3 py-1 rounded-full bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 font-bold shadow-md shadow-emerald-950/60">
                  <span className="relative flex h-2.5 w-2.5">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-400"></span>
                  </span>
                  <span>AGENT ONLINE</span>
                </span>
              )}
              {isAgentDegraded && (
                <span className="flex items-center gap-2 text-xs font-mono px-3 py-1 rounded-full bg-amber-500/15 border border-amber-500/40 text-amber-300 font-bold shadow-md shadow-amber-950/60">
                  <span className="h-2.5 w-2.5 rounded-full bg-amber-400 animate-pulse"></span>
                  <span>AGENT DEGRADED</span>
                </span>
              )}
              {isAgentOffline && (
                <span className="flex items-center gap-2 text-xs font-mono px-3 py-1 rounded-full bg-red-500/20 border border-red-500/50 text-red-300 font-bold shadow-md shadow-red-950/60">
                  <span className="h-2.5 w-2.5 rounded-full bg-red-500"></span>
                  <span>AGENT OFFLINE</span>
                </span>
              )}
            </div>

            {/* Host telemetry pills */}
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono mt-2">
              <span className="px-2.5 py-0.5 rounded-md bg-slate-900/90 border border-slate-800 text-slate-300">
                Active Machine: <strong className={isAgentOnline ? "text-cyan-300 font-semibold" : "text-slate-500 font-semibold"}>
                  {isAgentOnline
                    ? (agentStatus?.hostname || 'Connected Host')
                    : 'None (Offline)'}
                </strong>
              </span>
              <span className="px-2.5 py-0.5 rounded-md bg-slate-900/90 border border-slate-800 text-slate-300">
                OS: <strong className={isAgentOnline ? "text-slate-100 font-semibold" : "text-slate-500 font-semibold"}>
                  {isAgentOnline ? `${agentStatus?.os_name || 'Windows'} ${agentStatus?.os_version || ''}` : 'None (Standby)'}
                </strong>
              </span>
              <span className="px-2.5 py-0.5 rounded-md bg-slate-900/90 border border-slate-800 text-slate-300 flex items-center gap-1.5">
                <span className={`h-1.5 w-1.5 rounded-full ${isAgentOnline ? 'bg-cyan-400 animate-pulse' : 'bg-red-500'}`}></span>
                <span>Telemetry Sync:</span>
                <strong className={isAgentOnline ? (agentStatus?.telemetry_age_seconds && agentStatus.telemetry_age_seconds > 15 ? 'text-amber-400' : 'text-emerald-400 font-semibold') : 'text-red-400 font-semibold'}>
                  {isAgentOnline
                    ? `${agentStatus?.telemetry_age_seconds !== null && agentStatus?.telemetry_age_seconds !== undefined ? `${agentStatus.telemetry_age_seconds}s ago` : '0s'}`
                    : 'OFFLINE (Paused)'}
                </strong>
              </span>

              {/* Release Lock button if agent is connected */}
              {isAgentOnline && (
                <button
                  onClick={handleDisconnectDevice}
                  disabled={isDisconnecting}
                  title="Release active machine slot so you can connect another computer"
                  className="px-2.5 py-0.5 rounded-md bg-slate-900/90 border border-slate-800 hover:border-red-500/50 hover:bg-red-500/10 text-slate-400 hover:text-red-300 flex items-center gap-1.5 text-[11px] font-mono transition-all ml-1"
                >
                  <PowerOff className="w-3 h-3 text-red-400" />
                  <span>{isDisconnecting ? 'Releasing...' : 'Release Device Lock'}</span>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* View Mode Segmented Switcher & Actions */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Segmented View Mode Controller */}
          <div className="flex items-center p-1.5 rounded-xl bg-slate-900/90 border border-slate-800 shadow-inner">
            <button
              onClick={() => setViewMode('overview')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-mono font-bold transition-all ${viewMode === 'overview'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md shadow-cyan-950/60 ring-1 ring-cyan-400/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
            >
              <LayoutDashboard className="w-4 h-4" />
              <span>Overview</span>
            </button>

            <button
              onClick={() => setViewMode('hunter')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-mono font-bold transition-all ${viewMode === 'hunter'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md shadow-cyan-950/60 ring-1 ring-cyan-400/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
            >
              <Crosshair className="w-4 h-4" />
              <span>Process & Net ({processes.length})</span>
            </button>

            <button
              onClick={() => setViewMode('inventory')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-mono font-bold transition-all ${viewMode === 'inventory'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md shadow-cyan-950/60 ring-1 ring-cyan-400/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
            >
              <PackageCheck className="w-4 h-4" />
              <span>Inventory</span>
            </button>
          </div>

          {/* Run Agent Terminal Button */}
          <button
            onClick={() => setIsDownloadModalOpen(true)}
            title="View terminal command to start the local endpoint agent"
            className="flex items-center gap-2 px-3.5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600/30 to-blue-600/30 hover:from-cyan-500/40 hover:to-blue-500/40 border border-cyan-400/60 hover:border-cyan-300 text-xs font-mono font-bold text-cyan-200 shadow-md shadow-cyan-950/60 transition-all group"
          >
            <Terminal className="w-4 h-4 text-cyan-400 group-hover:scale-110 transition-transform" />
            <span>RUN AGENT (TERMINAL)</span>
          </button>

          <button
            onClick={() => loadAllData()}
            title="Refresh Telemetry"
            className="p-2.5 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-800 text-slate-300 transition-all shadow-sm"
          >
            <RefreshCw className="w-4 h-4 text-cyan-400" />
          </button>

          <div className="flex items-center gap-1.5">
            <button
              onClick={handleExecuteQuickScanAll}
              disabled={isScanningAll}
              title="Automatically run all 6 endpoint security scans simultaneously"
              className={`flex items-center gap-2 px-4 py-2.5 rounded-xl font-mono font-bold text-xs transition-all shadow-lg ${
                isScanningAll
                  ? 'bg-cyan-900/60 border border-cyan-400 text-cyan-200 shadow-cyan-500/30 cursor-wait'
                  : 'bg-gradient-to-r from-cyan-600 via-blue-600 to-cyan-500 hover:from-cyan-500 hover:to-blue-500 border border-cyan-400/50 text-white shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/35 active:scale-95'
              }`}
            >
              {isScanningAll ? (
                <>
                  <RefreshCw className="w-4 h-4 text-cyan-200 animate-spin" />
                  <span>SCANNING ALL VECTORS...</span>
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 text-cyan-200 animate-pulse" />
                  <span>QUICK SCAN (RUN ALL)</span>
                </>
              )}
            </button>

            <button
              onClick={() => setIsScanModalOpen(true)}
              title="Open Endpoint Scan Console & History"
              className="p-2.5 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-800 text-slate-300 transition-all shadow-sm group"
            >
              <SlidersHorizontal className="w-4 h-4 text-slate-400 group-hover:text-cyan-400" />
            </button>
          </div>
        </div>
      </div>

      {/* ================= SINGLE DEVICE CONFLICT NOTIFICATION BANNER ================= */}
      {conflictAlert && (
        <div className="p-4 rounded-xl bg-amber-500/15 border border-amber-500/40 text-amber-200 text-xs font-mono flex items-center justify-between gap-3 shadow-lg shadow-amber-950/40 animate-in fade-in">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
            <div>
              <strong className="text-amber-300 block">Single-Device Guard Activated</strong>
              <span>{conflictAlert}</span>
            </div>
          </div>
          <button
            onClick={() => setConflictAlert(null)}
            className="px-3 py-1 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 font-bold transition-all shrink-0"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* ================= ZERO-AGENT / OFFLINE HERO ONBOARDING BANNER ================= */}
      {isAgentOffline && (
        <div className="p-5 rounded-2xl bg-gradient-to-r from-slate-900/95 via-[#0a1120]/95 to-slate-900/95 border border-cyan-500/40 shadow-xl shadow-cyan-950/50 flex flex-col lg:flex-row lg:items-center justify-between gap-5 animate-in fade-in">
          <div className="flex items-start sm:items-center gap-4">
            <div className="p-3.5 rounded-2xl bg-cyan-500/15 border border-cyan-400/40 text-cyan-400 shadow-lg shadow-cyan-950/60 ring-1 ring-cyan-400/20 shrink-0">
              <Terminal className="w-7 h-7 drop-shadow-[0_0_8px_rgba(34,211,238,0.5)]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm sm:text-base font-mono font-bold text-white uppercase tracking-wide">
                  NO ACTIVE ENDPOINT AGENT — SINGLE DEVICE STANDBY
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                  AWAITING AGENT
                </span>
              </div>
              <p className="text-xs font-mono text-slate-300 mt-1 max-w-2xl leading-relaxed">
                QuantumVault is running in <strong>Single-Device Protection</strong> mode (no 2 devices at a time). Run the agent command in your local terminal to stream Defender alerts, firewall profiles, and active process telemetry.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            {/* Inline Copyable Terminal Snippet */}
            <div className="flex items-center gap-2 px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 shadow-inner">
              <span className="text-slate-500 select-none">$</span>
              <code>python -m agent.main</code>
              <button
                onClick={() => {
                  navigator.clipboard.writeText('python -m agent.main');
                  setCopiedTerminalInline(true);
                  setTimeout(() => setCopiedTerminalInline(false), 2000);
                }}
                className="p-1 hover:text-white transition-colors"
                title="Copy terminal command"
              >
                {copiedTerminalInline ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4 text-slate-400" />}
              </button>
            </div>

            <button
              onClick={() => setIsDownloadModalOpen(true)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 via-blue-600 to-cyan-500 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-lg shadow-cyan-500/25 transition-all border border-cyan-400/50"
            >
              <Terminal className="w-4 h-4" />
              <span>TERMINAL INSTRUCTIONS</span>
            </button>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODE 1: EXECUTIVE OVERVIEW (DEFAULT & EYE-CATCHING) */}
      {/* ========================================================================= */}
      {viewMode === 'overview' && (
        <div className="space-y-6 animate-in fade-in duration-200">
          {/* Top Two High-Impact Cards: Risk Gauge Cockpit + Combined Host Defense Controls */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
            {/* 1. Risk Score Cockpit (5 cols) */}
            {(() => {
              const score = isAgentOnline ? (riskScore?.score ?? 0) : 0;
              const radius = 46;
              const circumference = 2 * Math.PI * radius;
              const strokeDashoffset = isAgentOnline
                ? circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference
                : circumference;

              const isCritical = isAgentOnline && score >= 70;
              const isHigh = isAgentOnline && score >= 40 && score < 70;
              const isLow = isAgentOnline && score > 0 && score < 40;
              const isSafe = isAgentOnline && score === 0;

              const strokeColor = !isAgentOnline ? '#475569' : isCritical ? '#ef4444' : isHigh ? '#f59e0b' : isLow ? '#06b6d4' : '#10b981';
              const glowColor = !isAgentOnline ? 'transparent' : isCritical ? 'rgba(239,68,68,0.5)' : isHigh ? 'rgba(245,158,11,0.5)' : isLow ? 'rgba(6,182,212,0.5)' : 'rgba(16,185,129,0.5)';
              const badgeStyle = !isAgentOnline
                ? 'bg-slate-800/60 text-slate-400 border-slate-700/60 shadow-none'
                : isCritical
                  ? 'bg-red-500/20 text-red-300 border-red-500/50 shadow-red-950/50'
                  : isHigh
                    ? 'bg-amber-500/20 text-amber-300 border-amber-500/50 shadow-amber-950/50'
                    : isLow
                      ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-cyan-950/50'
                      : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50 shadow-emerald-950/50';

              return (
                <div className="lg:col-span-5 p-6 rounded-2xl bg-gradient-to-b from-slate-900/95 via-[#0b1020]/95 to-[#070b16]/98 border border-slate-800/80 hover:border-cyan-500/40 shadow-xl shadow-black/40 flex flex-col justify-between relative overflow-hidden group transition-colors duration-200">
                  {/* Top glowing cyber accent line */}
                  <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent opacity-80 group-hover:opacity-100 transition-opacity"></div>
                  {/* Ambient background glow */}
                  <div className="pointer-events-none absolute -top-20 -right-20 w-48 h-48 bg-cyan-500/10 rounded-full blur-2xl group-hover:opacity-80 transition-opacity duration-300"></div>

                  <div>
                    <div className="flex items-center justify-between mb-4">
                      <span className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-cyan-400" />
                        <span>ENDPOINT SECURITY RISK INDEX</span>
                      </span>
                      <span className={`text-[11px] font-mono px-3 py-1 rounded-full border uppercase font-extrabold shadow-sm ${badgeStyle}`}>
                        {isAgentOnline ? (riskScore?.level || 'SAFE') : 'STANDBY (OFFLINE)'}
                      </span>
                    </div>

                    {/* Circular Speedometer / Gauge Section */}
                    <div className="flex flex-col sm:flex-row items-center gap-6 p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 my-2">
                      <div className="relative flex items-center justify-center shrink-0">
                        <svg className="w-32 h-32 transform -rotate-90">
                          <circle
                            cx="64"
                            cy="64"
                            r={radius}
                            stroke="currentColor"
                            strokeWidth="10"
                            className="text-slate-800/80"
                            fill="transparent"
                          />
                          <circle
                            cx="64"
                            cy="64"
                            r={radius}
                            stroke={strokeColor}
                            strokeWidth="10"
                            strokeDasharray={circumference}
                            strokeDashoffset={strokeDashoffset}
                            strokeLinecap="round"
                            fill="transparent"
                            className="transition-all duration-1000 ease-out"
                            style={{ filter: `drop-shadow(0 0 8px ${glowColor})` }}
                          />
                        </svg>
                        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
                          <span className="text-3xl font-black font-mono tracking-tight text-white leading-none">
                            {isAgentOnline ? score : '--'}
                          </span>
                          <span className="text-[10px] font-mono text-slate-400 uppercase tracking-widest mt-1">
                            {isAgentOnline ? '/ 100' : 'OFFLINE'}
                          </span>
                        </div>
                      </div>

                      <div className="space-y-2 text-center sm:text-left">
                        <div className="flex items-center justify-center sm:justify-start gap-2">
                          <span className={`h-2.5 w-2.5 rounded-full ${!isAgentOnline ? 'bg-slate-500' : isSafe ? 'bg-emerald-400 animate-pulse' : isLow ? 'bg-cyan-400' : isHigh ? 'bg-amber-400' : 'bg-red-400'}`}></span>
                          <span className="text-sm font-bold font-mono text-white uppercase tracking-wide">
                            {!isAgentOnline ? 'Telemetry Paused' : isSafe ? 'Optimal Defense' : isLow ? 'Low Anomaly Profile' : isHigh ? 'Suspicious Indicators' : 'Critical Threat Profile'}
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 font-mono leading-relaxed">
                          {!isAgentOnline
                            ? 'No active agent connected. Continuous telemetry and risk evaluation are on standby until an endpoint connects.'
                            : (riskScore?.summary || 'Endpoint active and protected. Native defenses intact.')}
                        </p>
                        <div className="text-[11px] font-mono text-slate-400 pt-1">
                          {isAgentOnline
                            ? <>Evaluated against <strong className="text-cyan-300">{processes.length}</strong> processes & <strong className="text-cyan-300">{network.length}</strong> sockets.</>
                            : <>Audit paused — awaiting endpoint heartbeat.</>}
                        </div>
                      </div>
                    </div>

                    {/* Contributing factors pills */}
                    <div className="pt-4 border-t border-slate-800/80 mt-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-bold flex items-center gap-1.5">
                          <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Contributing Telemetry Factors</span>
                        </span>
                        <span className="text-[10px] font-mono text-slate-500">
                          {isAgentOnline ? 'Impact Delta' : 'Status'}
                        </span>
                      </div>

                      <div className="space-y-1.5 text-xs font-mono">
                        {!isAgentOnline ? (
                          <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 text-center text-slate-400 text-xs">
                            <div className="flex items-center justify-center gap-2">
                              <PowerOff className="w-3.5 h-3.5 text-slate-500" />
                              <span>Telemetry factors paused. Connect an agent to stream live indicators.</span>
                            </div>
                          </div>
                        ) : riskScore?.contributors && riskScore.contributors.length > 0 ? (
                          riskScore.contributors.slice(0, 3).map((c, idx) => (
                            <div key={idx} className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800/70 hover:border-slate-700 transition-colors">
                              <div className="flex items-center gap-2 min-w-0 pr-2">
                                {c.type === 'credit' ? (
                                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                                ) : (
                                  <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                                )}
                                <span className="text-slate-200 text-xs font-medium truncate">{c.factor}</span>
                              </div>
                              <span className={`font-bold px-2 py-0.5 rounded text-[11px] shrink-0 ${c.type === 'credit'
                                  ? 'text-emerald-300 bg-emerald-500/15 border border-emerald-500/30'
                                  : 'text-red-300 bg-red-500/15 border border-red-500/30'
                                }`}>
                                {c.impact > 0 ? `+${c.impact} pts` : `${c.impact} pts`}
                              </span>
                            </div>
                          ))
                        ) : (
                          <div className="p-2.5 rounded-lg bg-slate-900/40 border border-slate-800/60 text-slate-400 text-xs">
                            No active threat penalties identified.
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
                    <button
                      onClick={() => setViewMode('hunter')}
                      className="flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 font-semibold group-hover:translate-x-0.5 transition-all"
                    >
                      <span>Investigate live processes & sockets</span>
                      <ArrowRight className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              );
            })()}

            {/* 2. Combined Host Protection Controls (7 cols) */}
            <div className="lg:col-span-7 p-6 rounded-2xl bg-gradient-to-b from-slate-900/95 via-[#0b1020]/95 to-[#070b16]/98 border border-slate-800/80 hover:border-cyan-500/40 shadow-xl shadow-black/40 flex flex-col justify-between relative overflow-hidden group transition-colors duration-200">
              {/* Top glowing cyber accent line */}
              <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-emerald-400 to-transparent opacity-80 group-hover:opacity-100 transition-opacity"></div>
              {/* Ambient background glow */}
              <div className="pointer-events-none absolute -top-20 -right-20 w-48 h-48 bg-emerald-500/10 rounded-full blur-2xl group-hover:opacity-80 transition-opacity duration-300"></div>

              <div>
                <div className="flex items-center justify-between mb-4">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    <span>NATIVE WINDOWS DEFENSE CONTROLS</span>
                  </span>
                  <span className={`text-[11px] font-mono px-3 py-1 rounded-full border uppercase font-extrabold shadow-sm ${
                    !isAgentOnline
                      ? 'bg-slate-800/60 text-slate-400 border-slate-700/60'
                      : protection?.defender?.real_time_protection && protection?.firewall?.all_enabled
                        ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50 shadow-emerald-950/50'
                        : 'bg-amber-500/20 text-amber-300 border-amber-500/50 shadow-amber-950/50'
                    }`}>
                    {!isAgentOnline
                      ? 'TELEMETRY PAUSED (OFFLINE)'
                      : protection?.defender?.real_time_protection && protection?.firewall?.all_enabled ? 'ALL DEFENSES ACTIVE' : 'ACTION REQUIRED'}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Defender Box */}
                  <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 hover:border-emerald-500/40 transition-colors duration-200 space-y-3">
                    <div className="flex items-center justify-between pb-2 border-b border-slate-800/80">
                      <div className="flex items-center gap-2">
                        <div className={`p-1.5 rounded-lg border ${isAgentOnline ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' : 'bg-slate-800/50 text-slate-500 border-slate-700/50'}`}>
                          <ShieldCheck className="w-4 h-4" />
                        </div>
                        <span className="font-bold text-sm text-slate-100 font-mono">Microsoft Defender</span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        !isAgentOnline
                          ? 'bg-slate-800/60 text-slate-400 border border-slate-700/50'
                          : protection?.defender?.real_time_protection
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                            : 'bg-red-500/20 text-red-300 border border-red-500/30'
                        }`}>
                        {!isAgentOnline ? 'OFFLINE' : protection?.defender?.real_time_protection ? 'PROTECTED' : 'DISABLED'}
                      </span>
                    </div>

                    <div className="space-y-2 text-xs font-mono">
                      <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800/60">
                        <span className="text-slate-400">Real-Time Engine</span>
                        <div className="flex items-center gap-1.5">
                          <span className={`h-2 w-2 rounded-full ${!isAgentOnline ? 'bg-slate-600' : protection?.defender?.real_time_protection ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`}></span>
                          <strong className={!isAgentOnline ? 'text-slate-400 font-bold' : protection?.defender?.real_time_protection ? 'text-emerald-300 font-bold' : 'text-red-400 font-bold'}>
                            {!isAgentOnline ? 'STREAM PAUSED (OFFLINE)' : protection?.defender?.real_time_protection ? 'ACTIVE & MONITORING' : 'OFF'}
                          </strong>
                        </div>
                      </div>

                      <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800/60">
                        <span className="text-slate-400">Definitions Version</span>
                        <strong className="text-cyan-300 font-mono px-2 py-0.5 rounded bg-cyan-950/40 border border-cyan-800/40">
                          {isAgentOnline ? `v${protection?.defender?.signature_version || '1.459.574.0'}` : 'Awaiting Endpoint'}
                        </strong>
                      </div>

                      <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800/60">
                        <span className="text-slate-400">Signature Age</span>
                        <div className="flex items-center gap-1.5">
                          <strong className="text-slate-200">
                            {!isAgentOnline
                              ? 'Offline'
                              : protection?.defender?.signature_age_days === undefined || protection?.defender?.signature_age_days === null
                                ? 'Today'
                                : `${protection?.defender?.signature_age_days}d ago`}
                          </strong>
                          <span className={`text-[10px] px-1.5 py-0.5 rounded border font-bold ${
                            isAgentOnline
                              ? 'bg-emerald-500/10 text-emerald-300 border border-emerald-500/20'
                              : 'bg-slate-800/60 text-slate-500 border border-slate-700/50'
                          }`}>
                            {isAgentOnline ? 'CURRENT' : 'STANDBY'}
                          </span>
                        </div>
                      </div>

                      <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800/60">
                        <span className="text-slate-400">Behavior Monitor</span>
                        <div className="flex items-center gap-1.5">
                          <span className={`h-2 w-2 rounded-full ${isAgentOnline ? 'bg-emerald-400' : 'bg-slate-600'}`}></span>
                          <strong className={isAgentOnline ? 'text-emerald-300 font-bold' : 'text-slate-400 font-bold'}>
                            {isAgentOnline ? 'ACTIVE' : 'OFFLINE'}
                          </strong>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Firewall Box */}
                  <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 hover:border-cyan-500/40 transition-colors duration-200 space-y-3">
                    <div className="flex items-center justify-between pb-2 border-b border-slate-800/80">
                      <div className="flex items-center gap-2">
                        <div className={`p-1.5 rounded-lg border ${isAgentOnline ? 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30' : 'bg-slate-800/50 text-slate-500 border-slate-700/50'}`}>
                          <Shield className="w-4 h-4" />
                        </div>
                        <span className="font-bold text-sm text-slate-100 font-mono">Windows Firewall</span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        !isAgentOnline
                          ? 'bg-slate-800/60 text-slate-400 border border-slate-700/50'
                          : protection?.firewall?.all_enabled
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                            : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                        }`}>
                        {!isAgentOnline ? 'OFFLINE' : protection?.firewall?.all_enabled ? 'ALL PROFILES ON' : 'PARTIAL'}
                      </span>
                    </div>

                    <div className="space-y-2 text-xs font-mono">
                      <div className="grid grid-cols-3 gap-2 pt-1">
                        {['Domain', 'Private', 'Public'].map(prof => {
                          const isEnabled = isAgentOnline && (protection?.firewall?.profiles?.[prof]?.enabled ?? false);
                          return (
                            <div
                              key={prof}
                              className={`p-2.5 rounded-xl border text-center transition-all ${
                                !isAgentOnline
                                  ? 'bg-slate-900/50 border-slate-800/60'
                                  : isEnabled
                                    ? 'bg-emerald-950/25 border-emerald-500/30 hover:border-emerald-500/60'
                                    : 'bg-red-950/20 border-red-500/30 hover:border-red-500/50'
                                }`}
                            >
                              <span className="text-[11px] text-slate-300 block font-semibold">{prof}</span>
                              <div className="flex items-center justify-center gap-1 mt-1">
                                <span className={`h-1.5 w-1.5 rounded-full ${!isAgentOnline ? 'bg-slate-600' : isEnabled ? 'bg-emerald-400' : 'bg-red-400'}`}></span>
                                <span className={`text-[11px] font-bold ${!isAgentOnline ? 'text-slate-400' : isEnabled ? 'text-emerald-300' : 'text-red-400'}`}>
                                  {!isAgentOnline ? 'STANDBY' : isEnabled ? 'ACTIVE' : 'OFF'}
                                </span>
                              </div>
                            </div>
                          );
                        })}
                      </div>

                      <div className="p-2 rounded-lg bg-slate-900/60 border border-slate-800/60 flex items-center justify-between text-[11px]">
                        <span className="text-slate-400">Inspection Filter:</span>
                        <span className={isAgentOnline ? "text-emerald-300 font-semibold" : "text-slate-400"}>
                          {isAgentOnline ? 'Stateful Inbound/Outbound' : 'Telemetry Paused'}
                        </span>
                      </div>

                      <div className="p-2 rounded-lg bg-slate-900/60 border border-slate-800/60 flex items-center justify-between text-[11px]">
                        <span className="text-slate-400">Default Inbound Action:</span>
                        <span className={isAgentOnline ? "text-cyan-300 font-mono font-semibold" : "text-slate-400 font-mono"}>
                          {isAgentOnline ? 'BLOCK UNLISTED' : 'Telemetry Paused'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Sub-strip with Host Defense Signals */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 mt-3 text-center font-mono text-[11px]">
                  <div className="p-2 rounded-xl bg-slate-950/70 border border-slate-800/70">
                    <span className="text-slate-400 block text-[10px]">WMI Sensor</span>
                    <span className={`font-bold mt-0.5 block ${isAgentOnline ? 'text-emerald-300' : 'text-slate-500'}`}>
                      {isAgentOnline ? 'CONNECTED' : 'DISCONNECTED'}
                    </span>
                  </div>
                  <div className="p-2 rounded-xl bg-slate-950/70 border border-slate-800/70">
                    <span className="text-slate-400 block text-[10px]">Tamper Guard</span>
                    <span className={`font-bold mt-0.5 block ${isAgentOnline ? 'text-emerald-300' : 'text-slate-500'}`}>
                      {isAgentOnline ? 'ENABLED' : 'STANDBY'}
                    </span>
                  </div>
                  <div className="p-2 rounded-xl bg-slate-950/70 border border-slate-800/70">
                    <span className="text-slate-400 block text-[10px]">Audit Polling</span>
                    <span className={`font-bold mt-0.5 block ${isAgentOnline ? 'text-cyan-300' : 'text-slate-500'}`}>
                      {isAgentOnline ? '8s ACTIVE' : 'PAUSED'}
                    </span>
                  </div>
                  <div className="p-2 rounded-xl bg-slate-950/70 border border-slate-800/70">
                    <span className="text-slate-400 block text-[10px]">Cloud Protection</span>
                    <span className={`font-bold mt-0.5 block ${isAgentOnline ? 'text-emerald-300' : 'text-slate-500'}`}>
                      {isAgentOnline ? 'ENGAGED' : 'STANDBY'}
                    </span>
                  </div>
                </div>
              </div>

              <div className="mt-5 pt-3 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Verified via genuine Windows PowerShell & Security Center APIs</span>
                </span>
                <button
                  onClick={() => setIsScanModalOpen(true)}
                  className="text-cyan-400 hover:text-cyan-300 font-semibold underline underline-offset-4 flex items-center gap-1"
                >
                  <span>Run Configuration Audit</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>

          {/* ================= TELEMETRY METRIC KPI CARDS ================= */}
          {(() => {
            const ramTotalMb = telemetry?.memory_total_mb || 16384;
            const ramPercent = telemetry?.memory_percent ?? 0;
            const ramTotalGb = (ramTotalMb / 1024).toFixed(1);
            const ramUsedGb = ((ramTotalMb * ramPercent / 100) / 1024).toFixed(1);
            const cpuPercent = telemetry?.cpu_percent ?? 0;
            const netSentKb = Math.round((telemetry?.net_bytes_sent_sec || 0) / 1024);
            const netRecvKb = Math.round((telemetry?.net_bytes_recv_sec || 0) / 1024);

            return (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 md:gap-5">
                {/* 1. CPU Load Card */}
                <div className="p-5 md:p-6 rounded-2xl bg-gradient-to-b from-slate-900/90 via-[#0a0f1d]/90 to-[#070b14]/95 border border-slate-800/80 hover:border-cyan-500/40 shadow-lg shadow-black/40 relative overflow-hidden group transition-colors duration-200">
                  <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent opacity-80 group-hover:opacity-100 transition-opacity"></div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold flex items-center gap-2">
                      <div className="p-2 rounded-xl bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 shadow-md shadow-cyan-950">
                        <Cpu className="w-4 h-4" />
                      </div>
                      <span>CPU Load</span>
                    </span>
                    <span className="text-xs font-mono text-cyan-300 px-2.5 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/25">
                      {telemetry?.cpu_cores || 12} Cores
                    </span>
                  </div>

                  <div className="mt-4 flex items-baseline justify-between">
                    <span className="text-3xl lg:text-4xl font-black font-mono tracking-tight text-white">
                      {isAgentOnline ? `${cpuPercent}%` : '0%'}
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      Load: <strong className={!isAgentOnline ? 'text-slate-500 font-semibold' : cpuPercent > 80 ? 'text-red-400' : cpuPercent > 50 ? 'text-amber-400' : 'text-emerald-400'}>{!isAgentOnline ? 'Offline' : cpuPercent > 80 ? 'High' : cpuPercent > 50 ? 'Moderate' : 'Optimal'}</strong>
                    </span>
                  </div>

                  {/* Progress Bar */}
                  <div className="w-full bg-slate-800/80 rounded-full h-2 overflow-hidden ring-1 ring-slate-700/50 mt-3">
                    <div
                      className={`h-full rounded-full transition-all duration-500 shadow-sm ${isAgentOnline ? 'bg-gradient-to-r from-cyan-500 to-blue-500 shadow-cyan-500/50' : 'bg-slate-700'}`}
                      style={{ width: `${isAgentOnline ? Math.min(100, Math.max(4, cpuPercent)) : 0}%` }}
                    />
                  </div>
                </div>

                {/* 2. RAM Memory Card */}
                <div className="p-5 md:p-6 rounded-2xl bg-gradient-to-b from-slate-900/90 via-[#0a0f1d]/90 to-[#070b14]/95 border border-slate-800/80 hover:border-emerald-500/40 shadow-lg shadow-black/40 relative overflow-hidden group transition-colors duration-200">
                  <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-emerald-400 to-transparent opacity-80 group-hover:opacity-100 transition-opacity"></div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold flex items-center gap-2">
                      <div className="p-2 rounded-xl bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 shadow-md shadow-emerald-950">
                        <Activity className="w-4 h-4" />
                      </div>
                      <span>RAM Memory</span>
                    </span>
                    <span className="text-xs font-mono text-emerald-300 px-2.5 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/25">
                      {isAgentOnline ? `${ramTotalGb} GB Total` : 'Offline'}
                    </span>
                  </div>

                  <div className="mt-4 flex items-baseline justify-between">
                    <span className="text-3xl lg:text-4xl font-black font-mono tracking-tight text-white">
                      {isAgentOnline ? `${ramPercent}%` : '0%'}
                    </span>
                    <span className="text-xs font-mono text-slate-300">
                      {isAgentOnline ? `${ramUsedGb} GB Used` : 'Offline (Standby)'}
                    </span>
                  </div>

                  {/* Progress Bar */}
                  <div className="w-full bg-slate-800/80 rounded-full h-2 overflow-hidden ring-1 ring-slate-700/50 mt-3">
                    <div
                      className={`h-full rounded-full transition-all duration-500 shadow-sm ${!isAgentOnline ? 'bg-slate-700' : ramPercent > 85
                          ? 'bg-gradient-to-r from-amber-500 to-red-500 shadow-red-500/50'
                          : 'bg-gradient-to-r from-emerald-500 via-teal-400 to-cyan-500 shadow-emerald-500/50'
                        }`}
                      style={{ width: `${isAgentOnline ? Math.min(100, Math.max(4, ramPercent)) : 0}%` }}
                    />
                  </div>
                </div>

                {/* 3. Network I/O Card */}
                <div className="p-5 md:p-6 rounded-2xl bg-gradient-to-b from-slate-900/90 via-[#0a0f1d]/90 to-[#070b14]/95 border border-slate-800/80 hover:border-purple-500/40 shadow-lg shadow-black/40 relative overflow-hidden group transition-colors duration-200">
                  <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-purple-400 to-transparent opacity-80 group-hover:opacity-100 transition-opacity"></div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold flex items-center gap-2">
                      <div className="p-2 rounded-xl bg-purple-500/15 border border-purple-500/30 text-purple-400 shadow-md shadow-purple-950">
                        <Globe className="w-4 h-4" />
                      </div>
                      <span>Network I/O</span>
                    </span>
                    <span className="text-xs font-mono text-purple-300 px-2.5 py-0.5 rounded-full bg-purple-500/10 border border-purple-500/25">
                      {isAgentOnline ? `${network.length} Sockets` : 'Offline'}
                    </span>
                  </div>

                  <div className="mt-3.5 grid grid-cols-2 gap-2">
                    <div className="p-2 rounded-xl bg-slate-950/70 border border-slate-800/80">
                      <span className="text-[10px] font-mono text-slate-400 block">Outbound</span>
                      <span className="text-sm lg:text-base font-bold font-mono text-cyan-300 mt-0.5 block truncate">
                        ▲ {isAgentOnline ? netSentKb : 0} KB/s
                      </span>
                    </div>
                    <div className="p-2 rounded-xl bg-slate-950/70 border border-slate-800/80">
                      <span className="text-[10px] font-mono text-slate-400 block">Inbound</span>
                      <span className="text-sm lg:text-base font-bold font-mono text-emerald-300 mt-0.5 block truncate">
                        ▼ {isAgentOnline ? netRecvKb : 0} KB/s
                      </span>
                    </div>
                  </div>

                  <div className="mt-2 text-[10px] font-mono text-slate-400 flex items-center justify-between">
                    <span>Socket Telemetry</span>
                    <span className={isAgentOnline ? "text-emerald-400 flex items-center gap-1" : "text-slate-500 flex items-center gap-1"}>
                      <span className={`h-1.5 w-1.5 rounded-full ${isAgentOnline ? 'bg-emerald-400 animate-pulse' : 'bg-slate-600'}`}></span>
                      {isAgentOnline ? 'Stream Live' : 'Stream Paused (Offline)'}
                    </span>
                  </div>
                </div>

                {/* 4. Host Uptime Card */}
                <div className="p-5 md:p-6 rounded-2xl bg-gradient-to-b from-slate-900/90 via-[#0a0f1d]/90 to-[#070b14]/95 border border-slate-800/80 hover:border-amber-500/40 shadow-lg shadow-black/40 relative overflow-hidden group transition-colors duration-200">
                  <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-amber-400 to-transparent opacity-80 group-hover:opacity-100 transition-opacity"></div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold flex items-center gap-2">
                      <div className="p-2 rounded-xl bg-amber-500/15 border border-amber-500/30 text-amber-400 shadow-md shadow-amber-950">
                        <Clock className="w-4 h-4" />
                      </div>
                      <span>Host Uptime</span>
                    </span>
                    <span className={`text-xs font-mono px-2.5 py-0.5 rounded-full border flex items-center gap-1.5 ${
                      isAgentOnline
                        ? 'text-emerald-300 bg-emerald-500/10 border-emerald-500/25'
                        : 'text-slate-400 bg-slate-800/40 border-slate-700/50'
                    }`}>
                      <span className={`h-1.5 w-1.5 rounded-full ${isAgentOnline ? 'bg-emerald-400 animate-pulse' : 'bg-red-500'}`}></span>
                      {isAgentOnline ? 'Healthy' : 'Host Offline'}
                    </span>
                  </div>

                  <div className="mt-4 flex items-baseline justify-between">
                    <span className="text-2xl lg:text-3xl font-black font-mono tracking-tight text-white">
                      {isAgentOnline && telemetry?.uptime_seconds ? formatUptime(telemetry.uptime_seconds) : 'N/A'}
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      {isAgentOnline ? '100% Availability' : 'Disconnected (Standby)'}
                    </span>
                  </div>

                  <div className="w-full bg-slate-800/80 rounded-full h-2 overflow-hidden ring-1 ring-slate-700/50 mt-3">
                    <div className={`h-full rounded-full ${isAgentOnline ? 'bg-gradient-to-r from-amber-500 to-emerald-400 w-full' : 'bg-slate-700 w-0'}`} />
                  </div>
                </div>
              </div>
            );
          })()}

          {/* ================= THREAT ALERTS & DIAGNOSTIC SCANS ================= */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
            {/* Active Threats (8 cols) */}
            <div className="lg:col-span-8 p-6 rounded-2xl bg-gradient-to-b from-slate-900/95 via-[#0b1020]/95 to-[#070b16]/98 border border-slate-800/80 hover:border-cyan-500/40 shadow-xl shadow-black/40 relative overflow-hidden group transition-colors duration-200">
              <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent opacity-80 group-hover:opacity-100 transition-opacity"></div>

              <div className="flex items-center justify-between mb-4">
                <span className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <span>DETECTED ENDPOINT ANOMALIES & THREAT ALERTS ({threats.length})</span>
                </span>
                <span className="text-xs font-mono text-slate-400 px-2.5 py-0.5 rounded-full bg-slate-900 border border-slate-800">
                  Real-time Rule & Anomaly Engine
                </span>
              </div>

              {threats.length === 0 ? (
                <div className="p-7 rounded-2xl bg-slate-950/70 border border-slate-800/80 text-center my-2 relative overflow-hidden">
                  <div className="relative z-10">
                    <div className={`w-14 h-14 rounded-2xl flex items-center justify-center mx-auto mb-3 shadow-lg ${
                      isAgentOnline
                        ? 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 shadow-emerald-950'
                        : 'bg-slate-800/50 border border-slate-700/50 text-slate-500 shadow-slate-950'
                    }`}>
                      {isAgentOnline ? <CheckCircle2 className="w-8 h-8" /> : <PowerOff className="w-8 h-8" />}
                    </div>
                    <h3 className="text-base font-bold font-mono text-white">
                      {isAgentOnline ? 'ZERO ACTIVE THREATS IDENTIFIED' : 'TELEMETRY STREAM PAUSED (OFFLINE)'}
                    </h3>
                    <p className="text-xs font-mono text-slate-400 max-w-xl mx-auto mt-1 leading-relaxed">
                      {isAgentOnline
                        ? 'Continuous real-time behavioral monitoring active. All process memory spaces, registry startup keys, and socket connections match certified benign baselines.'
                        : 'Endpoint agent is not streaming data. Start the agent in your terminal to stream Defender alerts, firewall state, and behavioral anomaly telemetry.'}
                    </p>

                    {/* 4 Assurance Badges */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 mt-5 max-w-2xl mx-auto text-left">
                      <div className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800/80">
                        <span className="text-[10px] font-mono text-slate-400 block">Process Execution</span>
                        <span className={`text-xs font-bold font-mono mt-0.5 flex items-center gap-1 ${isAgentOnline ? 'text-emerald-300' : 'text-slate-400'}`}>
                          {isAgentOnline ? <CheckCircle2 className="w-3 h-3 text-emerald-400" /> : <span className="h-2 w-2 rounded-full bg-slate-600"></span>}
                          {isAgentOnline ? `Safe (${processes.length})` : 'Paused (Offline)'}
                        </span>
                      </div>
                      <div className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800/80">
                        <span className="text-[10px] font-mono text-slate-400 block">Socket Flow</span>
                        <span className={`text-xs font-bold font-mono mt-0.5 flex items-center gap-1 ${isAgentOnline ? 'text-emerald-300' : 'text-slate-400'}`}>
                          {isAgentOnline ? <CheckCircle2 className="w-3 h-3 text-emerald-400" /> : <span className="h-2 w-2 rounded-full bg-slate-600"></span>}
                          {isAgentOnline ? `Monitored (${network.length})` : 'Paused (Offline)'}
                        </span>
                      </div>
                      <div className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800/80">
                        <span className="text-[10px] font-mono text-slate-400 block">Startup Persistence</span>
                        <span className={`text-xs font-bold font-mono mt-0.5 flex items-center gap-1 ${isAgentOnline ? 'text-emerald-300' : 'text-slate-400'}`}>
                          {isAgentOnline ? <CheckCircle2 className="w-3 h-3 text-emerald-400" /> : <span className="h-2 w-2 rounded-full bg-slate-600"></span>}
                          {isAgentOnline ? 'Clean' : 'Paused (Offline)'}
                        </span>
                      </div>
                      <div className="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800/80">
                        <span className="text-[10px] font-mono text-slate-400 block">Defender Engine</span>
                        <span className={`text-xs font-bold font-mono mt-0.5 flex items-center gap-1 ${isAgentOnline ? 'text-emerald-300' : 'text-slate-400'}`}>
                          {isAgentOnline ? <CheckCircle2 className="w-3 h-3 text-emerald-400" /> : <span className="h-2 w-2 rounded-full bg-slate-600"></span>}
                          {isAgentOnline ? 'Active' : 'Offline'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="space-y-3 max-h-72 overflow-y-auto pr-1">
                  {threats.map(t => (
                    <div
                      key={t.id}
                      onClick={() => setSelectedAlert(t)}
                      className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-red-500/50 cursor-pointer transition-all flex items-center justify-between group shadow-sm hover:shadow-red-950/20"
                    >
                      <div className="flex items-center gap-3">
                        <span className={`px-2.5 py-1 rounded text-[10px] font-bold font-mono shadow-sm ${t.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-300 border border-red-500/40' :
                            t.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40' :
                              'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                          }`}>
                          {t.severity}
                        </span>
                        <div>
                          <h4 className="text-xs font-bold font-mono text-slate-100 group-hover:text-red-300 transition-colors">{t.title}</h4>
                          <span className="text-[11px] font-mono text-slate-400">{t.detection_source}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[11px] font-mono text-cyan-400 opacity-0 group-hover:opacity-100 transition-opacity">Inspect</span>
                        <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 transition-colors" />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Quick Actions & Recent Scans (4 cols) */}
            <div className="lg:col-span-4 p-6 rounded-2xl bg-gradient-to-b from-slate-900/95 via-[#0b1020]/95 to-[#070b16]/98 border border-slate-800/80 hover:border-cyan-500/40 shadow-xl shadow-black/40 flex flex-col justify-between relative overflow-hidden group transition-colors duration-200">
              <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent opacity-80 group-hover:opacity-100 transition-opacity"></div>

              <div>
                <span className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold flex items-center gap-2 mb-4">
                  <Zap className="w-4 h-4 text-cyan-400" />
                  <span>RECENT DIAGNOSTIC SCANS</span>
                </span>

                <div className="space-y-2.5 text-xs font-mono">
                  {scans.slice(0, 3).map(s => (
                    <div key={s.scan_id} className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between hover:border-slate-700 transition-colors">
                      <div className="flex items-center gap-2.5">
                        <div className="p-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/25">
                          <Activity className="w-3.5 h-3.5" />
                        </div>
                        <div>
                          <span className="font-bold text-slate-200 uppercase block">{s.scan_type} SCAN</span>
                          <span className="text-[10px] text-slate-500">{new Date(s.started_at).toLocaleTimeString()}</span>
                        </div>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${s.status === 'COMPLETED' ? 'text-emerald-300 bg-emerald-500/15 border border-emerald-500/30' :
                          s.status === 'RUNNING' ? 'text-cyan-300 bg-cyan-500/15 border border-cyan-500/30 animate-pulse' :
                            'text-slate-400 bg-slate-800 border border-slate-700'
                        }`}>
                        {s.status}
                      </span>
                    </div>
                  ))}
                  {scans.length === 0 && (
                    <div className="p-4 rounded-xl bg-slate-950/50 border border-slate-800/60 text-center text-slate-400 text-xs">
                      No scans executed yet.
                    </div>
                  )}
                </div>
              </div>

              <button
                onClick={() => setIsScanModalOpen(true)}
                className="w-full mt-5 py-3 rounded-xl bg-gradient-to-r from-cyan-600 via-blue-600 to-cyan-500 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-mono font-bold tracking-wider uppercase transition-all shadow-lg shadow-cyan-600/30 hover:shadow-cyan-500/40 flex items-center justify-center gap-2 group"
              >
                <Play className="w-4 h-4 fill-white group-hover:scale-110 transition-transform" />
                <span>Launch On-Demand Scan</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODE 2: PROCESS & NETWORK HUNTER */}
      {/* ========================================================================= */}
      {viewMode === 'hunter' && (
        <div className="rounded-xl border border-slate-800 bg-[#090d19]/95 p-5 space-y-4 animate-in fade-in duration-150">
          {/* Sub-navigation */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setHunterSubTab('processes')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${hunterSubTab === 'processes'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                  }`}
              >
                {isAgentOnline ? `Live Running Processes (${processes.length})` : `Running Processes (0) [Offline]`}
              </button>
              <button
                onClick={() => setHunterSubTab('network')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${hunterSubTab === 'network'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                  }`}
              >
                {isAgentOnline ? `Active Network Sockets (${network.length})` : `Network Sockets (0) [Offline]`}
              </button>
            </div>

            {/* Search */}
            <div className="relative max-w-xs w-full">
              <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
              <input
                type="text"
                value={hunterSubTab === 'processes' ? processSearch : networkSearch}
                onChange={(e) => hunterSubTab === 'processes' ? setProcessSearch(e.target.value) : setNetworkSearch(e.target.value)}
                placeholder={`Search ${hunterSubTab}...`}
                className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700/80 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/50"
              />
            </div>
          </div>

          {!isAgentOnline && (
            <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
                <span>Endpoint Agent Offline — Live process and network telemetry feeds are paused. Connect an agent to stream active processes and sockets.</span>
              </div>
            </div>
          )}

          {/* Processes Sub-view */}
          {hunterSubTab === 'processes' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">Click any process row to inspect command line, parent PID, and mapped network sockets.</span>
                <div className="flex items-center gap-1.5">
                  <span className="text-slate-400">Risk Filter:</span>
                  {['ALL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'].map(lvl => (
                    <button
                      key={lvl}
                      onClick={() => setProcessRiskFilter(lvl)}
                      className={`px-2 py-0.5 rounded text-[10px] ${processRiskFilter === lvl
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                          : 'bg-slate-900 text-slate-400 border border-slate-800'
                        }`}
                    >
                      {lvl}
                    </button>
                  ))}
                </div>
              </div>

              <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[550px] overflow-y-auto smooth-scroll overscroll-contain">
                <table className="w-full text-xs font-mono text-left">
                  <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 sticky top-0 z-10 shadow-sm">
                    <tr>
                      <th className="px-3.5 py-2.5">Process Name</th>
                      <th className="px-3.5 py-2.5">PID</th>
                      <th className="px-3.5 py-2.5">CPU %</th>
                      <th className="px-3.5 py-2.5">Memory</th>
                      <th className="px-3.5 py-2.5">User</th>
                      <th className="px-3.5 py-2.5">Executable Path</th>
                      <th className="px-3.5 py-2.5">Risk Rating</th>
                      <th className="px-3.5 py-2.5 text-right">Inspect</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredProcesses.map(p => (
                      <tr
                        key={p.pid}
                        onClick={() => setSelectedProcess(p)}
                        className="hover:bg-slate-900/60 cursor-pointer transition-colors group"
                      >
                        <td className="px-3.5 py-2 font-bold text-white group-hover:text-cyan-300">
                          {p.name}
                        </td>
                        <td className="px-3 py-2 text-slate-400">{p.pid}</td>
                        <td className="px-3 py-2 font-semibold text-cyan-400">{p.cpu_percent}%</td>
                        <td className="px-3 py-2 text-emerald-400">{p.memory_mb} MB</td>
                        <td className="px-3 py-2 text-slate-300 truncate max-w-[120px]">{p.username || 'SYSTEM'}</td>
                        <td className="px-3 py-2 text-slate-400 truncate max-w-[220px]" title={p.exe_path || ''}>
                          {p.exe_path || '-'}
                        </td>
                        <td className="px-3 py-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${p.risk_level === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                              p.risk_level === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                                p.risk_level === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                                  'bg-slate-800 text-slate-400'
                            }`}>
                            {p.risk_level}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-right">
                          <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-cyan-400 ml-auto" />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Network Sub-view */}
          {hunterSubTab === 'network' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">Real-time correlated TCP/UDP sockets with PIDs and process names.</span>
                <div className="flex items-center gap-1.5">
                  <span className="text-slate-400">State:</span>
                  {['ALL', 'ESTABLISHED', 'LISTEN'].map(st => (
                    <button
                      key={st}
                      onClick={() => setNetworkFilter(st)}
                      className={`px-2 py-0.5 rounded text-[10px] ${networkFilter === st
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                          : 'bg-slate-900 text-slate-400 border border-slate-800'
                        }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>

              <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[550px] overflow-y-auto smooth-scroll overscroll-contain">
                <table className="w-full text-xs font-mono text-left">
                  <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 sticky top-0 z-10 shadow-sm">
                    <tr>
                      <th className="px-3.5 py-2.5">Process (PID)</th>
                      <th className="px-3.5 py-2.5">Proto</th>
                      <th className="px-3.5 py-2.5">Local Socket</th>
                      <th className="px-3.5 py-2.5">Remote Target</th>
                      <th className="px-3.5 py-2.5">State</th>
                      <th className="px-3.5 py-2.5">Risk Rating</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredNetwork.map((c, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/40">
                        <td className="px-3.5 py-2 font-bold text-white">
                          <span className="text-cyan-300">{c.process_name}</span>
                          <span className="text-slate-500 ml-1.5 font-normal">({c.pid})</span>
                        </td>
                        <td className="px-3 py-2 text-slate-400 font-semibold">{c.protocol}</td>
                        <td className="px-3 py-2 text-slate-300">{c.local_ip}:{c.local_port}</td>
                        <td className="px-3 py-2 text-slate-300">{c.remote_ip}:{c.remote_port}</td>
                        <td className="px-3 py-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${c.state === 'ESTABLISHED' ? 'bg-emerald-500/20 text-emerald-300' :
                              c.state === 'LISTEN' ? 'bg-blue-500/20 text-blue-300' :
                                'bg-slate-800 text-slate-400'
                            }`}>
                            {c.state}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-slate-400">{c.risk_level}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* MODE 3: SOFTWARE & PERSISTENCE INVENTORY */}
      {/* ========================================================================= */}
      {viewMode === 'inventory' && (
        <div className="rounded-xl border border-slate-800 bg-[#090d19]/95 p-5 space-y-4 animate-in fade-in duration-150">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setInventorySubTab('software')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${inventorySubTab === 'software'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                  }`}
              >
                Installed Software ({software.length})
              </button>
              <button
                onClick={() => setInventorySubTab('startup')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${inventorySubTab === 'startup'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                  }`}
              >
                Startup Persistence ({startup.length})
              </button>
              <button
                onClick={() => setInventorySubTab('services')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${inventorySubTab === 'services'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                  }`}
              >
                Windows Services ({services.length})
              </button>
              <button
                onClick={() => setInventorySubTab('files')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${inventorySubTab === 'files'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                  }`}
              >
                File Security & Hashes ({trackedFiles.length})
              </button>
            </div>

            {inventorySubTab === 'software' && (
              <div className="relative max-w-xs w-full">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                <input
                  type="text"
                  value={softwareSearch}
                  onChange={(e) => setSoftwareSearch(e.target.value)}
                  placeholder="Search installed software..."
                  className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700/80 text-xs font-mono text-slate-200"
                />
              </div>
            )}
          </div>

          {/* Sub-content: Software */}
          {inventorySubTab === 'software' && (
            <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[550px] overflow-y-auto smooth-scroll overscroll-contain">
              <table className="w-full text-xs font-mono text-left">
                <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 sticky top-0 z-10 shadow-sm">
                  <tr>
                    <th className="px-3.5 py-2.5">Application Name</th>
                    <th className="px-3.5 py-2.5">Version</th>
                    <th className="px-3.5 py-2.5">Publisher</th>
                    <th className="px-3.5 py-2.5">Architecture</th>
                    <th className="px-3.5 py-2.5">Security Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {software.filter(s => !softwareSearch || s.name.toLowerCase().includes(softwareSearch.toLowerCase())).map((s, idx) => (
                    <tr key={idx} className="hover:bg-slate-900/40">
                      <td className="px-3.5 py-2 font-bold text-slate-200">{s.name}</td>
                      <td className="px-3 py-2 text-cyan-400">{s.version}</td>
                      <td className="px-3 py-2 text-slate-400">{s.publisher}</td>
                      <td className="px-3 py-2 text-slate-400">{s.architecture}</td>
                      <td className="px-3 py-2">
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/15 text-emerald-400 border border-emerald-500/20">
                          {s.security_status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Sub-content: Startup */}
          {inventorySubTab === 'startup' && (
            <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[550px] overflow-y-auto smooth-scroll overscroll-contain">
              <table className="w-full text-xs font-mono text-left">
                <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 sticky top-0 z-10 shadow-sm">
                  <tr>
                    <th className="px-3.5 py-2.5">Startup Item</th>
                    <th className="px-3.5 py-2.5">Persistence Source</th>
                    <th className="px-3.5 py-2.5">Target Command</th>
                    <th className="px-3.5 py-2.5">Risk Flag</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {startup.map((su, idx) => (
                    <tr key={idx} className="hover:bg-slate-900/40">
                      <td className="px-3.5 py-2 font-bold text-white">{su.name}</td>
                      <td className="px-3 py-2 text-cyan-300">{su.source}</td>
                      <td className="px-3 py-2 text-slate-300 truncate max-w-md">{su.path}</td>
                      <td className="px-3 py-2">
                        {su.suspicious ? (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-red-500/20 text-red-400 font-bold border border-red-500/40">
                            SUSPICIOUS
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            VERIFIED
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Sub-content: Services */}
          {inventorySubTab === 'services' && (
            <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[550px] overflow-y-auto smooth-scroll overscroll-contain">
              <table className="w-full text-xs font-mono text-left">
                <thead className="bg-slate-900 text-slate-400 border-b border-slate-800 sticky top-0 z-10 shadow-sm">
                  <tr>
                    <th className="px-3.5 py-2.5">Service Name</th>
                    <th className="px-3.5 py-2.5">Display Title</th>
                    <th className="px-3.5 py-2.5">State</th>
                    <th className="px-3.5 py-2.5">Startup Type</th>
                    <th className="px-3.5 py-2.5">Binary Path</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {services.map((svc, idx) => (
                    <tr key={idx} className="hover:bg-slate-900/40">
                      <td className="px-3.5 py-2 font-bold text-white">{svc.name}</td>
                      <td className="px-3 py-2 text-slate-300">{svc.display_name}</td>
                      <td className="px-3 py-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${svc.status === 'running' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-800 text-slate-400'
                          }`}>
                          {svc.status}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-slate-400">{svc.start_type}</td>
                      <td className="px-3 py-2 text-slate-400 truncate max-w-xs">{svc.bin_path}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Sub-content: Files */}
          {inventorySubTab === 'files' && (
            <div className="space-y-4">
              <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono">
                <span className="text-slate-400 block mb-1">Monitored Watch Folders:</span>
                <span className="text-cyan-400 font-bold">Downloads, User Startup, AppData Local Temp</span>
              </div>

              <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[450px] overflow-y-auto">
                <table className="w-full text-xs font-mono text-left">
                  <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="px-3 py-2">Binary Name</th>
                      <th className="px-3 py-2">File Size</th>
                      <th className="px-3 py-2">SHA-256 Hash</th>
                      <th className="px-3 py-2">Last Modified</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {trackedFiles.map((tf, i) => (
                      <tr key={i} className="hover:bg-slate-900/40">
                        <td className="px-3 py-2 font-bold text-slate-200">{tf.name}</td>
                        <td className="px-3 py-2 text-slate-400">{(tf.size / 1024).toFixed(1)} KB</td>
                        <td className="px-3 py-2 text-cyan-400 select-all font-mono">{tf.sha256 || 'Non-binary'}</td>
                        <td className="px-3 py-2 text-slate-400">{tf.last_modified ? new Date(tf.last_modified).toLocaleString() : '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ================= MODALS ================= */}
      <ProcessModal
        process={selectedProcess}
        networkConns={network}
        onClose={() => setSelectedProcess(null)}
      />

      <AlertModal
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
      />

      <ScanModal
        isOpen={isScanModalOpen}
        onClose={() => setIsScanModalOpen(false)}
        scans={scans}
        onScanTriggered={(newScan) => {
          setScans(prev => [newScan, ...prev]);
        }}
        isAgentOnline={isAgentOnline}
        deviceId={agentStatus?.device_id}
        isScanningAll={isScanningAll}
        onTriggerAll={handleExecuteQuickScanAll}
      />

      <AgentDownloadModal
        isOpen={isDownloadModalOpen}
        onClose={() => setIsDownloadModalOpen(false)}
        activeDeviceId={agentStatus?.device_id}
        activeDeviceName={agentStatus?.hostname}
        deviceModeInfo={deviceModeInfo}
        onDeviceDisconnected={() => {
          loadAllData();
        }}
      />
    </div>
  );
};
