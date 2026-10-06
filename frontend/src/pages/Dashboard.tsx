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
  ArrowRight
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
  fetchRiskScore,
  getCommandCenterWebSocketUrl
} from '../services/commandCenterApi';

import { ProcessModal } from '../components/command-center/ProcessModal';
import { AlertModal } from '../components/command-center/AlertModal';
import { ScanModal } from '../components/command-center/ScanModal';

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

  // WebSocket ref
  const wsRef = useRef<WebSocket | null>(null);

  // Initial Full Load
  const loadAllData = async () => {
    try {
      const [
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
        fetchAgentStatus(),
        fetchSystemTelemetry(),
        fetchTelemetryHistory(),
        fetchProtectionStatus(),
        fetchRiskScore(),
        fetchProcesses(),
        fetchNetwork(),
        fetchThreats(),
        fetchSecurityEvents(),
        fetchFileEvents(),
        fetchScans()
      ]);

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

  // WebSocket Setup with auto-reconnect
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
            } else if (data.type === 'threats_update') {
              setThreats(data.threats);
              if (data.risk) setRiskScore(data.risk);
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
      fetchAgentStatus().then(st => setAgentStatus(st)).catch(() => {});
    }, 8000);

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
    <div className="space-y-5 text-slate-100 max-w-7xl mx-auto">
      {/* ================= TOP HEADER ================= */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-lg font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Shield className="w-5 h-5 text-cyan-400" />
              <span>ENDPOINT COMMAND CENTER</span>
            </h1>

            {/* Live Status Badge */}
            {isAgentOnline && (
              <span className="flex items-center gap-1.5 text-xs font-mono px-2.5 py-0.5 rounded-full bg-emerald-500/15 border border-emerald-500/40 text-emerald-400 font-semibold shadow-sm shadow-emerald-950">
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span>AGENT ONLINE</span>
              </span>
            )}
            {isAgentDegraded && (
              <span className="flex items-center gap-1.5 text-xs font-mono px-2.5 py-0.5 rounded-full bg-amber-500/15 border border-amber-500/40 text-amber-400 font-semibold">
                <span className="h-2 w-2 rounded-full bg-amber-400"></span>
                <span>AGENT DEGRADED</span>
              </span>
            )}
            {isAgentOffline && (
              <span className="flex items-center gap-1.5 text-xs font-mono px-2.5 py-0.5 rounded-full bg-red-500/20 border border-red-500/50 text-red-400 font-semibold">
                <span className="h-2 w-2 rounded-full bg-red-500"></span>
                <span>AGENT OFFLINE</span>
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-x-3 text-xs text-slate-400 font-mono mt-1">
            <span>Host: <strong className="text-slate-200">{agentStatus?.hostname || 'Unknown'}</strong></span>
            <span>•</span>
            <span>OS: <strong className="text-slate-200">{agentStatus?.os_name || 'Windows'} {agentStatus?.os_version || ''}</strong></span>
            <span>•</span>
            <span>
              Telemetry Age: <strong className={agentStatus?.telemetry_age_seconds && agentStatus.telemetry_age_seconds > 15 ? 'text-amber-400' : 'text-cyan-400'}>
                {agentStatus?.telemetry_age_seconds !== null && agentStatus?.telemetry_age_seconds !== undefined ? `${agentStatus.telemetry_age_seconds}s` : '0s'}
              </strong>
            </span>
          </div>
        </div>

        {/* View Mode Segmented Switcher & Actions */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Segmented View Mode Controller */}
          <div className="flex items-center p-1 rounded-xl bg-slate-900 border border-slate-800 shadow-inner">
            <button
              onClick={() => setViewMode('overview')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                viewMode === 'overview'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md shadow-cyan-950'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <LayoutDashboard className="w-3.5 h-3.5" />
              <span>Overview</span>
            </button>

            <button
              onClick={() => setViewMode('hunter')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                viewMode === 'hunter'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md shadow-cyan-950'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Crosshair className="w-3.5 h-3.5" />
              <span>Process & Net ({processes.length})</span>
            </button>

            <button
              onClick={() => setViewMode('inventory')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                viewMode === 'inventory'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-md shadow-cyan-950'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <PackageCheck className="w-3.5 h-3.5" />
              <span>Software & Persistence</span>
            </button>
          </div>

          <button
            onClick={loadAllData}
            title="Refresh Telemetry"
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-cyan-500/40 text-slate-300 transition-colors"
          >
            <RefreshCw className="w-4 h-4 text-cyan-400" />
          </button>

          <button
            onClick={() => setIsScanModalOpen(true)}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-cyan-500/30 text-xs font-mono font-semibold text-cyan-300 transition-all shadow-sm"
          >
            <Zap className="w-3.5 h-3.5 text-cyan-400" />
            <span>EXECUTE SCAN</span>
          </button>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* MODE 1: EXECUTIVE OVERVIEW (DEFAULT & CLEAN) */}
      {/* ========================================================================= */}
      {viewMode === 'overview' && (
        <div className="space-y-5 animate-in fade-in duration-150">
          {/* Top Two Clean Cards: Risk Gauge + Combined Host Protection */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* 1. Risk Score Cockpit (5 cols) */}
            <div className="lg:col-span-5 p-5 rounded-xl bg-[#090d19]/90 border border-slate-800/90 shadow-sm flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-cyan-400" />
                    <span>ENDPOINT SECURITY RISK</span>
                  </span>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${
                    riskScore?.level === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border-red-500/40' :
                    riskScore?.level === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border-orange-500/40' :
                    riskScore?.level === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400 border-amber-500/40' :
                    'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                  }`}>
                    {riskScore?.level || 'SAFE'}
                  </span>
                </div>

                <div className="flex items-center gap-4 my-3">
                  <div className="flex items-baseline">
                    <span className="text-5xl font-black font-mono tracking-tight text-white">
                      {riskScore?.score ?? 0}
                    </span>
                    <span className="text-sm font-mono text-slate-400 ml-1">/ 100</span>
                  </div>
                  <p className="text-xs text-slate-300 font-mono leading-relaxed">
                    {riskScore?.summary || 'Endpoint active and protected.'}
                  </p>
                </div>

                {/* Contributing factors pills */}
                <div className="pt-3 border-t border-slate-800/80">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold block mb-2">
                    Key Contributing Telemetry Factors
                  </span>
                  <div className="space-y-1 text-xs font-mono">
                    {riskScore?.contributors && riskScore.contributors.length > 0 ? (
                      riskScore.contributors.slice(0, 3).map((c, idx) => (
                        <div key={idx} className="flex items-center justify-between py-0.5">
                          <span className="text-slate-300 truncate max-w-[280px]">{c.factor}</span>
                          <span className={`font-bold ${c.type === 'credit' ? 'text-emerald-400' : 'text-red-400'}`}>
                            {c.impact > 0 ? `+${c.impact}` : `${c.impact}`}
                          </span>
                        </div>
                      ))
                    ) : (
                      <span className="text-slate-500 text-xs">No active risk penalties identified.</span>
                    )}
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-cyan-400">
                <button
                  onClick={() => setViewMode('hunter')}
                  className="flex items-center gap-1 hover:underline text-xs"
                >
                  <span>Investigate processes & network</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* 2. Combined Host Protection Controls (7 cols) */}
            <div className="lg:col-span-7 p-5 rounded-xl bg-[#090d19]/90 border border-slate-800/90 shadow-sm flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-4">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-cyan-400" />
                    <span>NATIVE WINDOWS DEFENSE CONTROLS</span>
                  </span>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${
                    protection?.defender?.real_time_protection && protection?.firewall?.all_enabled
                      ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                      : 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                  }`}>
                    {protection?.defender?.real_time_protection && protection?.firewall?.all_enabled ? 'ALL DEFENSES ACTIVE' : 'ACTION REQUIRED'}
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Defender Box */}
                  <div className="p-3.5 rounded-lg bg-slate-900/80 border border-slate-800/90 space-y-2 text-xs font-mono">
                    <div className="flex items-center justify-between pb-1.5 border-b border-slate-800">
                      <span className="font-bold text-slate-200">Microsoft Defender</span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        protection?.defender?.real_time_protection ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'
                      }`}>
                        {protection?.defender?.real_time_protection ? 'PROTECTED' : 'DISABLED'}
                      </span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Real-Time Engine</span>
                      <strong className={protection?.defender?.real_time_protection ? 'text-emerald-400' : 'text-red-400'}>
                        {protection?.defender?.real_time_protection ? 'ACTIVE' : 'OFF'}
                      </strong>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Definitions Version</span>
                      <strong className="text-slate-200">{protection?.defender?.signature_version || 'Unknown'}</strong>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Signature Age</span>
                      <strong className="text-slate-200">{protection?.defender?.signature_age_days ?? 0} day(s) ago</strong>
                    </div>
                  </div>

                  {/* Firewall Box */}
                  <div className="p-3.5 rounded-lg bg-slate-900/80 border border-slate-800/90 space-y-2 text-xs font-mono">
                    <div className="flex items-center justify-between pb-1.5 border-b border-slate-800">
                      <span className="font-bold text-slate-200">Windows Firewall</span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        protection?.firewall?.all_enabled ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'
                      }`}>
                        {protection?.firewall?.all_enabled ? 'ALL PROFILES ON' : 'PARTIAL'}
                      </span>
                    </div>

                    <div className="grid grid-cols-3 gap-1.5 pt-1">
                      {['Domain', 'Private', 'Public'].map(prof => {
                        const isEnabled = protection?.firewall?.profiles?.[prof]?.enabled ?? false;
                        return (
                          <div key={prof} className="p-2 rounded bg-slate-950/80 border border-slate-800 text-center">
                            <span className="text-[10px] text-slate-400 block">{prof}</span>
                            <span className={`text-[10px] font-bold block mt-0.5 ${isEnabled ? 'text-emerald-400' : 'text-red-400'}`}>
                              {isEnabled ? 'ON' : 'OFF'}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
                <span>Verified via genuine Windows PowerShell & Security Center APIs</span>
                <button
                  onClick={() => setIsScanModalOpen(true)}
                  className="text-cyan-400 hover:underline"
                >
                  Run Configuration Audit
                </button>
              </div>
            </div>
          </div>

          {/* Compact Telemetry Strip (4 Horizontal Metrics) */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800/90 flex items-center justify-between">
              <div>
                <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
                  <Cpu className="w-3.5 h-3.5 text-cyan-400" /> CPU Load
                </span>
                <span className="text-xl font-bold font-mono text-white mt-0.5 block">
                  {telemetry?.cpu_percent ?? 0}%
                </span>
              </div>
              <span className="text-xs font-mono text-slate-500">{telemetry?.cpu_cores || 8} Cores</span>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800/90 flex items-center justify-between">
              <div>
                <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
                  <Activity className="w-3.5 h-3.5 text-emerald-400" /> RAM Memory
                </span>
                <span className="text-xl font-bold font-mono text-white mt-0.5 block">
                  {telemetry?.memory_percent ?? 0}%
                </span>
              </div>
              <span className="text-xs font-mono text-slate-500">{Math.round((telemetry?.memory_total_mb || 0) / 1024)} GB</span>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800/90 flex items-center justify-between">
              <div>
                <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
                  <Globe className="w-3.5 h-3.5 text-purple-400" /> Network
                </span>
                <span className="text-sm font-bold font-mono text-cyan-300 mt-0.5 block">
                  ▲ {Math.round((telemetry?.net_bytes_sent_sec || 0) / 1024)} KB/s
                </span>
              </div>
              <span className="text-sm font-bold font-mono text-emerald-300">
                ▼ {Math.round((telemetry?.net_bytes_recv_sec || 0) / 1024)} KB/s
              </span>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800/90 flex items-center justify-between">
              <div>
                <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
                  <Clock className="w-3.5 h-3.5 text-amber-400" /> Host Uptime
                </span>
                <span className="text-base font-bold font-mono text-slate-100 mt-0.5 block">
                  {telemetry?.uptime_seconds ? formatUptime(telemetry.uptime_seconds) : 'N/A'}
                </span>
              </div>
              <span className="text-xs font-mono text-slate-500">Live</span>
            </div>
          </div>

          {/* Active Threat Alerts & Scans Strip */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* Active Threats (8 cols) */}
            <div className="lg:col-span-8 p-5 rounded-xl bg-[#090d19]/90 border border-slate-800/90">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <span>DETECTED ENDPOINT ANOMALIES & THREAT ALERTS ({threats.length})</span>
                </span>
                <span className="text-[11px] font-mono text-slate-500">Real-time Rule Engine</span>
              </div>

              {threats.length === 0 ? (
                <div className="p-6 rounded-lg bg-slate-900/40 border border-slate-800 text-center my-2">
                  <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-1.5" />
                  <p className="text-xs font-mono text-slate-300">No active threat alerts or suspicious processes flagged.</p>
                  <p className="text-[11px] font-mono text-slate-500 mt-0.5">All monitored startup entries, network ports, and processes match safe baselines.</p>
                </div>
              ) : (
                <div className="space-y-2.5 max-h-56 overflow-y-auto">
                  {threats.map(t => (
                    <div
                      key={t.id}
                      onClick={() => setSelectedAlert(t)}
                      className="p-3 rounded-lg bg-slate-900/70 border border-slate-800 hover:border-red-500/40 cursor-pointer transition-colors flex items-center justify-between"
                    >
                      <div className="flex items-center gap-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          t.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                          t.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                          'bg-amber-500/20 text-amber-400'
                        }`}>
                          {t.severity}
                        </span>
                        <div>
                          <h4 className="text-xs font-bold font-mono text-slate-200">{t.title}</h4>
                          <span className="text-[11px] font-mono text-slate-400">{t.detection_source}</span>
                        </div>
                      </div>
                      <ChevronRight className="w-4 h-4 text-slate-500" />
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Quick Actions & Recent Scans (4 cols) */}
            <div className="lg:col-span-4 p-5 rounded-xl bg-[#090d19]/90 border border-slate-800/90 flex flex-col justify-between">
              <div>
                <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-2 mb-3">
                  <Zap className="w-4 h-4 text-cyan-400" />
                  <span>RECENT DIAGNOSTIC SCANS</span>
                </span>

                <div className="space-y-2 text-xs font-mono">
                  {scans.slice(0, 3).map(s => (
                    <div key={s.scan_id} className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 flex items-center justify-between">
                      <div>
                        <span className="font-bold text-slate-200 uppercase block">{s.scan_type} Scan</span>
                        <span className="text-[10px] text-slate-500">{new Date(s.started_at).toLocaleTimeString()}</span>
                      </div>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        s.status === 'COMPLETED' ? 'text-emerald-400 bg-emerald-500/10' :
                        s.status === 'RUNNING' ? 'text-cyan-400 bg-cyan-500/10 animate-pulse' :
                        'text-slate-400 bg-slate-800'
                      }`}>
                        {s.status}
                      </span>
                    </div>
                  ))}
                  {scans.length === 0 && (
                    <p className="text-slate-500 text-xs py-2">No scans executed yet.</p>
                  )}
                </div>
              </div>

              <button
                onClick={() => setIsScanModalOpen(true)}
                className="w-full mt-4 py-2 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-bold transition-all flex items-center justify-center gap-2"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Launch New Scan</span>
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
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                  hunterSubTab === 'processes'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Live Running Processes ({processes.length})
              </button>
              <button
                onClick={() => setHunterSubTab('network')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                  hunterSubTab === 'network'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Active Network Sockets ({network.length})
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
                      className={`px-2 py-0.5 rounded text-[10px] ${
                        processRiskFilter === lvl
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                          : 'bg-slate-900 text-slate-400 border border-slate-800'
                      }`}
                    >
                      {lvl}
                    </button>
                  ))}
                </div>
              </div>

              <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[550px] overflow-y-auto">
                <table className="w-full text-xs font-mono text-left">
                  <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 sticky top-0 z-10 backdrop-blur-sm">
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
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            p.risk_level === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
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
                      className={`px-2 py-0.5 rounded text-[10px] ${
                        networkFilter === st
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                          : 'bg-slate-900 text-slate-400 border border-slate-800'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>

              <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[550px] overflow-y-auto">
                <table className="w-full text-xs font-mono text-left">
                  <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 sticky top-0 z-10 backdrop-blur-sm">
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
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            c.state === 'ESTABLISHED' ? 'bg-emerald-500/20 text-emerald-300' :
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
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                  inventorySubTab === 'software'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Installed Software ({software.length})
              </button>
              <button
                onClick={() => setInventorySubTab('startup')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                  inventorySubTab === 'startup'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Startup Persistence ({startup.length})
              </button>
              <button
                onClick={() => setInventorySubTab('services')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                  inventorySubTab === 'services'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Windows Services ({services.length})
              </button>
              <button
                onClick={() => setInventorySubTab('files')}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                  inventorySubTab === 'files'
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
            <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[550px] overflow-y-auto">
              <table className="w-full text-xs font-mono text-left">
                <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 sticky top-0 z-10 backdrop-blur-sm">
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
            <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[550px] overflow-y-auto">
              <table className="w-full text-xs font-mono text-left">
                <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 sticky top-0 z-10 backdrop-blur-sm">
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
            <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[550px] overflow-y-auto">
              <table className="w-full text-xs font-mono text-left">
                <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 sticky top-0 z-10 backdrop-blur-sm">
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
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          svc.status === 'running' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-slate-800 text-slate-400'
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
      />
    </div>
  );
};
