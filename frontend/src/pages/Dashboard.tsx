import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Activity,
  Cpu,
  HardDrive,
  Globe,
  Radio,
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
  Info,
  ChevronRight,
  ExternalLink,
  Zap,
  Server
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

interface DashboardProps {
  onNavigate?: (tab: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = () => {
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
  const [activeTab, setActiveTab] = useState<'processes' | 'network' | 'threats' | 'events' | 'inventory' | 'files'>('processes');
  const [inventorySubTab, setInventorySubTab] = useState<'software' | 'services' | 'startup'>('software');
  
  // Filters & Search
  const [processSearch, setProcessSearch] = useState('');
  const [processRiskFilter, setProcessRiskFilter] = useState('ALL');
  const [networkFilter, setNetworkFilter] = useState('ALL');
  const [networkSearch, setNetworkSearch] = useState('');
  const [softwareSearch, setSoftwareSearch] = useState('');
  const [eventSeverityFilter, setEventSeverityFilter] = useState('ALL');

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
      console.error('Error loading initial command center data:', e);
    } finally {
      setLoading(false);
    }
  };

  // Load secondary data on tab switch
  useEffect(() => {
    if (activeTab === 'inventory') {
      if (inventorySubTab === 'software' && software.length === 0) {
        fetchSoftware().then(setSoftware);
      } else if (inventorySubTab === 'services' && services.length === 0) {
        fetchServices().then(setServices);
      } else if (inventorySubTab === 'startup' && startup.length === 0) {
        fetchStartup().then(setStartup);
      }
    } else if (activeTab === 'files' && trackedFiles.length === 0) {
      fetchTrackedFiles().then(setTrackedFiles);
    }
  }, [activeTab, inventorySubTab]);

  // WebSocket Setup with Reconnect
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
          // WebSocket connected
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
            } else if (data.type === 'security_events_update') {
              setEvents(data.events);
            } else if (data.type === 'file_events_update') {
              setFileEvents(data.events);
            } else if (data.type === 'scan_update') {
              setScans(prev => {
                const next = [...prev];
                const idx = next.findIndex(s => s.scan_id === data.scan.scan_id);
                if (idx >= 0) next[idx] = data.scan;
                else next.unshift(data.scan);
                return next;
              });
            }
          } catch (err) {
            // Non-json or ping-pong
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

    // Secondary Polling interval (every 8s) to ensure resilience
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

  // Filtered Events
  const filteredEvents = useMemo(() => {
    return events.filter(e => {
      if (eventSeverityFilter === 'ALL') return true;
      return e.severity === eventSeverityFilter;
    });
  }, [events, eventSeverityFilter]);

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
    <div className="space-y-6 text-slate-100">
      {/* ================= TOP HEADER ================= */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2.5">
              <span>QUANTUM VAULT COMMAND CENTER</span>
            </h1>
            
            {/* Live Connection Badge */}
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
              <span className="flex items-center gap-1.5 text-xs font-mono px-2.5 py-0.5 rounded-full bg-red-500/20 border border-red-500/50 text-red-400 font-semibold shadow-sm shadow-red-950">
                <span className="h-2 w-2 rounded-full bg-red-500"></span>
                <span>AGENT OFFLINE</span>
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400 font-mono mt-1.5">
            <span>
              Host: <strong className="text-slate-200">{agentStatus?.hostname || 'Unknown'}</strong>
            </span>
            <span>•</span>
            <span>
              OS: <strong className="text-slate-200">{agentStatus?.os_name || 'Windows'} {agentStatus?.os_version || ''}</strong>
            </span>
            <span>•</span>
            <span>
              {agentStatus?.telemetry_age_seconds !== null && agentStatus?.telemetry_age_seconds !== undefined ? (
                <>Telemetry Age: <strong className={agentStatus.telemetry_age_seconds > 15 ? 'text-amber-400' : 'text-cyan-400'}>{agentStatus.telemetry_age_seconds}s</strong></>
              ) : (
                <>Last telemetry: <strong className="text-slate-400">{agentStatus?.last_telemetry_at ? new Date(agentStatus.last_telemetry_at).toLocaleTimeString() : 'N/A'}</strong></>
              )}
            </span>
          </div>
        </div>

        {/* Header Actions */}
        <div className="flex items-center gap-2">
          <button
            onClick={loadAllData}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700/80 hover:border-cyan-500/40 text-xs font-mono text-slate-300 transition-all"
          >
            <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
            <span>REFRESH</span>
          </button>

          <button
            onClick={() => setIsScanModalOpen(true)}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-xs font-mono font-semibold text-white shadow-lg shadow-cyan-950 transition-all"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>EXECUTE SCAN</span>
          </button>
        </div>
      </div>

      {/* ================= ROW 1: RISK SCORE & PROTECTION STATUS ================= */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* OVERALL RISK SCORE (5 cols) */}
        <div className="lg:col-span-5 p-5 rounded-xl bg-[#090d19]/90 border border-slate-800/90 shadow-inner flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                <span>OVERALL SECURITY RISK SCORE</span>
              </span>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${
                riskScore?.level === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border-red-500/40' :
                riskScore?.level === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border-orange-500/40' :
                riskScore?.level === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400 border-amber-500/40' :
                riskScore?.level === 'LOW' ? 'bg-blue-500/20 text-blue-400 border-blue-500/40' :
                'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
              }`}>
                {riskScore?.level || 'SAFE'} RISK
              </span>
            </div>

            <div className="flex items-baseline gap-3 mb-4">
              <span className="text-4xl font-black font-mono tracking-tight text-white">
                {riskScore?.score ?? 0}
              </span>
              <span className="text-sm font-mono text-slate-400">/ 100</span>
              <p className="text-xs text-slate-400 font-mono ml-auto">
                {riskScore?.summary || 'Endpoint active and protected.'}
              </p>
            </div>

            {/* Risk Breakdown Progress Bars */}
            <div className="space-y-2 mb-4 text-xs font-mono">
              {riskScore?.breakdown && Object.entries(riskScore.breakdown).map(([cat, val]) => (
                <div key={cat} className="space-y-0.5">
                  <div className="flex justify-between text-[11px] text-slate-400">
                    <span>{cat}</span>
                    <span className={val > 0 ? 'text-amber-400 font-bold' : 'text-slate-400'}>{val} pts</span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${val > 20 ? 'bg-red-500' : val > 10 ? 'bg-amber-500' : 'bg-cyan-500'}`}
                      style={{ width: `${Math.min(val * 2.5, 100)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Contributing Factors */}
          <div className="pt-3 border-t border-slate-800/80">
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 font-semibold block mb-2">
              Contributing Telemetry Factors
            </span>
            <div className="space-y-1 text-xs font-mono max-h-24 overflow-y-auto">
              {riskScore?.contributors && riskScore.contributors.length > 0 ? (
                riskScore.contributors.map((c, idx) => (
                  <div key={idx} className="flex items-center justify-between text-xs">
                    <span className="text-slate-300 truncate max-w-[280px]">{c.factor}</span>
                    <span className={`font-bold ${c.type === 'credit' ? 'text-emerald-400' : 'text-red-400'}`}>
                      {c.impact > 0 ? `+${c.impact}` : `${c.impact}`}
                    </span>
                  </div>
                ))
              ) : (
                <span className="text-slate-500 text-xs">No negative telemetry contributors.</span>
              )}
            </div>
          </div>
        </div>

        {/* PROTECTION STATUS (7 cols) */}
        <div className="lg:col-span-7 grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Microsoft Defender Card */}
          <div className="p-5 rounded-xl bg-[#090d19]/90 border border-slate-800/90 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-400" />
                  <span>MICROSOFT DEFENDER</span>
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${
                  protection?.defender?.real_time_protection ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40' : 'bg-red-500/20 text-red-400 border-red-500/40'
                }`}>
                  {protection?.defender?.available ? (protection?.defender?.real_time_protection ? 'PROTECTED' : 'DISABLED') : 'UNAVAILABLE'}
                </span>
              </div>

              <div className="space-y-2 text-xs font-mono mt-3">
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Real-Time Protection</span>
                  <span className={protection?.defender?.real_time_protection ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold'}>
                    {protection?.defender?.real_time_protection ? 'ACTIVE' : 'DISABLED'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Antivirus Engine</span>
                  <span className={protection?.defender?.antivirus_enabled ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold'}>
                    {protection?.defender?.antivirus_enabled ? 'ENABLED' : 'DISABLED'}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Definitions Version</span>
                  <span className="text-slate-200">{protection?.defender?.signature_version || 'Unknown'}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Signature Age</span>
                  <span className={(protection?.defender?.signature_age_days ?? 0) > 3 ? 'text-amber-400' : 'text-slate-200'}>
                    {protection?.defender?.signature_age_days !== undefined ? `${protection.defender.signature_age_days} day(s) ago` : 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-slate-400">Last Quick Scan</span>
                  <span className="text-slate-200">
                    {protection?.defender?.quick_scan_age_days !== undefined ? `${protection.defender.quick_scan_age_days} day(s) ago` : 'N/A'}
                  </span>
                </div>
              </div>
            </div>

            <div className="mt-3 pt-2 text-[11px] font-mono text-slate-500">
              Running Mode: {protection?.defender?.am_running_mode || 'Normal'}
            </div>
          </div>

          {/* Windows Firewall Card */}
          <div className="p-5 rounded-xl bg-[#090d19]/90 border border-slate-800/90 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-2">
                  <Globe className="w-4 h-4 text-cyan-400" />
                  <span>WINDOWS FIREWALL</span>
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${
                  protection?.firewall?.all_enabled ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40' : 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                }`}>
                  {protection?.firewall?.all_enabled ? 'ALL ACTIVE' : 'PARTIAL'}
                </span>
              </div>

              <div className="space-y-3 mt-3 text-xs font-mono">
                {protection?.firewall?.profiles && Object.entries(protection.firewall.profiles).map(([prof, data]) => (
                  <div key={prof} className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80 flex items-center justify-between">
                    <div>
                      <span className="font-bold text-slate-200 block">{prof} Profile</span>
                      <span className="text-[10px] text-slate-400">Inbound: {data.default_inbound || 'Block'}</span>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                      data.enabled ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30' : 'bg-red-500/20 text-red-400 border-red-500/30'
                    }`}>
                      {data.enabled ? 'ENABLED' : 'DISABLED'}
                    </span>
                  </div>
                ))}
                {!protection?.firewall?.profiles && (
                  <p className="text-slate-500 text-xs">Firewall status query awaiting telemetry.</p>
                )}
              </div>
            </div>

            <div className="mt-3 pt-2 text-[11px] font-mono text-slate-500">
              State: Real Windows Advanced Firewall Policy
            </div>
          </div>
        </div>
      </div>

      {/* ================= ROW 2: LIVE SYSTEM TELEMETRY GAUGES ================= */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
        {/* CPU */}
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800/80 relative overflow-hidden">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1">
            <span className="flex items-center gap-1.5"><Cpu className="w-3.5 h-3.5 text-cyan-400" /> CPU Load</span>
            <span>{telemetry?.cpu_cores || 8} Cores</span>
          </div>
          <div className="text-2xl font-bold font-mono text-white mb-2">
            {telemetry?.cpu_percent ?? 0}%
          </div>
          <div className="h-10 -mx-4 -mb-4">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={telemetryHistory.slice(-20)}>
                <Area type="monotone" dataKey="cpu_percent" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.2} isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* RAM */}
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800/80 relative overflow-hidden">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1">
            <span className="flex items-center gap-1.5"><Activity className="w-3.5 h-3.5 text-emerald-400" /> Memory</span>
            <span>{Math.round((telemetry?.memory_total_mb || 0) / 1024)} GB</span>
          </div>
          <div className="text-2xl font-bold font-mono text-white mb-2">
            {telemetry?.memory_percent ?? 0}%
          </div>
          <div className="h-10 -mx-4 -mb-4">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={telemetryHistory.slice(-20)}>
                <Area type="monotone" dataKey="memory_percent" stroke="#10b981" fill="#10b981" fillOpacity={0.2} isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Disk */}
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800/80">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1">
            <span className="flex items-center gap-1.5"><HardDrive className="w-3.5 h-3.5 text-blue-400" /> System Disk</span>
            <span>C:\</span>
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {telemetry?.disk_percent ?? 0}%
          </div>
          <div className="text-[11px] font-mono text-slate-400 mt-1">
            {telemetry?.disk_used_gb || 0} / {telemetry?.disk_total_gb || 0} GB
          </div>
        </div>

        {/* Network I/O Rate */}
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800/80">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1">
            <span className="flex items-center gap-1.5"><Globe className="w-3.5 h-3.5 text-purple-400" /> Net Throughput</span>
            <span>Live</span>
          </div>
          <div className="text-base font-bold font-mono text-cyan-300">
            ▲ {Math.round((telemetry?.net_bytes_sent_sec || 0) / 1024)} KB/s
          </div>
          <div className="text-base font-bold font-mono text-emerald-300">
            ▼ {Math.round((telemetry?.net_bytes_recv_sec || 0) / 1024)} KB/s
          </div>
        </div>

        {/* Host Uptime */}
        <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800/80">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1">
            <span className="flex items-center gap-1.5"><Clock className="w-3.5 h-3.5 text-amber-400" /> System Uptime</span>
            <span>Boot</span>
          </div>
          <div className="text-xl font-bold font-mono text-slate-100">
            {telemetry?.uptime_seconds ? formatUptime(telemetry.uptime_seconds) : 'N/A'}
          </div>
          <div className="text-[10px] font-mono text-slate-400 mt-1 truncate">
            {telemetry?.architecture || 'x86_64'}
          </div>
        </div>
      </div>

      {/* ================= ROW 3: INTERACTIVE SOC WORKSPACE ================= */}
      <div className="rounded-xl border border-slate-800 bg-[#090d1a]/95 overflow-hidden shadow-2xl">
        {/* Navigation Tabs Header */}
        <div className="flex flex-wrap items-center justify-between px-4 pt-3 border-b border-slate-800 bg-slate-900/50">
          <div className="flex items-center gap-1 overflow-x-auto">
            <button
              onClick={() => setActiveTab('processes')}
              className={`px-3.5 py-2 text-xs font-mono font-semibold rounded-t-lg transition-all flex items-center gap-2 ${
                activeTab === 'processes'
                  ? 'bg-[#090d1a] text-cyan-300 border-t-2 border-cyan-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>Processes ({processes.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('network')}
              className={`px-3.5 py-2 text-xs font-mono font-semibold rounded-t-lg transition-all flex items-center gap-2 ${
                activeTab === 'network'
                  ? 'bg-[#090d1a] text-cyan-300 border-t-2 border-cyan-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>Network ({network.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('threats')}
              className={`px-3.5 py-2 text-xs font-mono font-semibold rounded-t-lg transition-all flex items-center gap-2 ${
                activeTab === 'threats'
                  ? 'bg-[#090d1a] text-cyan-300 border-t-2 border-cyan-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
              <span>Threat Alerts ({threats.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('events')}
              className={`px-3.5 py-2 text-xs font-mono font-semibold rounded-t-lg transition-all flex items-center gap-2 ${
                activeTab === 'events'
                  ? 'bg-[#090d1a] text-cyan-300 border-t-2 border-cyan-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              <span>Security Events ({events.length})</span>
            </button>

            <button
              onClick={() => setActiveTab('inventory')}
              className={`px-3.5 py-2 text-xs font-mono font-semibold rounded-t-lg transition-all flex items-center gap-2 ${
                activeTab === 'inventory'
                  ? 'bg-[#090d1a] text-cyan-300 border-t-2 border-cyan-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Software & Persistence</span>
            </button>

            <button
              onClick={() => setActiveTab('files')}
              className={`px-3.5 py-2 text-xs font-mono font-semibold rounded-t-lg transition-all flex items-center gap-2 ${
                activeTab === 'files'
                  ? 'bg-[#090d1a] text-cyan-300 border-t-2 border-cyan-400'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCode2 className="w-3.5 h-3.5" />
              <span>File Security ({fileEvents.length})</span>
            </button>
          </div>
        </div>

        {/* Tab Body Content */}
        <div className="p-4 sm:p-6">
          {/* ================= TAB 1: PROCESSES ================= */}
          {activeTab === 'processes' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="relative flex-1 max-w-md">
                  <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={processSearch}
                    onChange={(e) => setProcessSearch(e.target.value)}
                    placeholder="Search process by name or PID..."
                    className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700/80 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/50"
                  />
                </div>

                <div className="flex items-center gap-2 text-xs font-mono">
                  <span className="text-slate-400">Filter Risk:</span>
                  {['ALL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'].map(lvl => (
                    <button
                      key={lvl}
                      onClick={() => setProcessRiskFilter(lvl)}
                      className={`px-2 py-1 rounded text-[11px] font-mono transition-colors ${
                        processRiskFilter === lvl
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                          : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                      }`}
                    >
                      {lvl}
                    </button>
                  ))}
                </div>
              </div>

              {/* Process Table */}
              <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[500px] overflow-y-auto">
                <table className="w-full text-xs font-mono text-left">
                  <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 sticky top-0 z-10 backdrop-blur-sm">
                    <tr>
                      <th className="px-3.5 py-2.5">Process Name</th>
                      <th className="px-3 py-2.5">PID</th>
                      <th className="px-3 py-2.5">CPU %</th>
                      <th className="px-3 py-2.5">Memory</th>
                      <th className="px-3 py-2.5">User</th>
                      <th className="px-3 py-2.5">Executable Path</th>
                      <th className="px-3 py-2.5">Risk Rating</th>
                      <th className="px-3 py-2.5 text-right">Inspect</th>
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

          {/* ================= TAB 2: NETWORK ================= */}
          {activeTab === 'network' && (
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="relative flex-1 max-w-md">
                  <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={networkSearch}
                    onChange={(e) => setNetworkSearch(e.target.value)}
                    placeholder="Search by IP, port or process..."
                    className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700/80 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500/50"
                  />
                </div>

                <div className="flex items-center gap-2 text-xs font-mono">
                  <span className="text-slate-400">State:</span>
                  {['ALL', 'ESTABLISHED', 'LISTEN'].map(st => (
                    <button
                      key={st}
                      onClick={() => setNetworkFilter(st)}
                      className={`px-2.5 py-1 rounded text-[11px] font-mono transition-colors ${
                        networkFilter === st
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                          : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>

              {/* Network Table */}
              <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[500px] overflow-y-auto">
                <table className="w-full text-xs font-mono text-left">
                  <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 sticky top-0 z-10 backdrop-blur-sm">
                    <tr>
                      <th className="px-3.5 py-2.5">Process (PID)</th>
                      <th className="px-3 py-2.5">Proto</th>
                      <th className="px-3 py-2.5">Local Address</th>
                      <th className="px-3 py-2.5">Remote Target</th>
                      <th className="px-3 py-2.5">Socket State</th>
                      <th className="px-3 py-2.5">Risk Rating</th>
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
                            c.state === 'ESTABLISHED' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' :
                            c.state === 'LISTEN' ? 'bg-blue-500/20 text-blue-300 border border-blue-500/30' :
                            'bg-slate-800 text-slate-400'
                          }`}>
                            {c.state}
                          </span>
                        </td>
                        <td className="px-3 py-2">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                            c.risk_level === 'HIGH' ? 'bg-red-500/20 text-red-400' : 'text-slate-400'
                          }`}>
                            {c.risk_level}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ================= TAB 3: THREAT ALERTS ================= */}
          {activeTab === 'threats' && (
            <div className="space-y-4">
              {threats.length === 0 ? (
                <div className="p-8 rounded-xl bg-slate-900/40 border border-slate-800 text-center">
                  <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
                  <h4 className="text-sm font-bold text-slate-200 font-mono">No Active Threat Anomalies</h4>
                  <p className="text-xs text-slate-400 font-mono mt-1">
                    Telemetry collectors currently detect no suspicious processes, disabled protections, or unauthorized persistence entries.
                  </p>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {threats.map(alert => (
                    <div
                      key={alert.id}
                      onClick={() => setSelectedAlert(alert)}
                      className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-red-500/40 cursor-pointer transition-all flex flex-col justify-between"
                    >
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${
                            alert.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border-red-500/40' :
                            alert.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border-orange-500/40' :
                            'bg-amber-500/20 text-amber-400 border-amber-500/40'
                          }`}>
                            {alert.severity} RISK
                          </span>
                          <span className="text-[11px] font-mono text-slate-400">
                            {new Date(alert.created_at).toLocaleTimeString()}
                          </span>
                        </div>
                        <h4 className="text-sm font-bold text-slate-100 font-mono mb-1.5">{alert.title}</h4>
                        <p className="text-xs text-slate-400 font-mono line-clamp-2 mb-3">
                          {alert.explanation}
                        </p>
                      </div>

                      <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
                        <span className="text-cyan-400">{alert.detection_source}</span>
                        <span className="text-slate-400 flex items-center gap-1 group-hover:text-white">
                          View Evidence <ChevronRight className="w-3.5 h-3.5" />
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ================= TAB 4: SECURITY EVENTS ================= */}
          {activeTab === 'events' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400">
                  Real Windows Event Log Stream (System, Application, Security)
                </span>
                <div className="flex items-center gap-1.5 text-xs font-mono">
                  {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
                    <button
                      key={sev}
                      onClick={() => setEventSeverityFilter(sev)}
                      className={`px-2 py-0.5 rounded text-[11px] ${
                        eventSeverityFilter === sev
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                          : 'bg-slate-900 text-slate-400 border border-slate-800'
                      }`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>

              <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[500px] overflow-y-auto">
                <table className="w-full text-xs font-mono text-left">
                  <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 sticky top-0 z-10 backdrop-blur-sm">
                    <tr>
                      <th className="px-3.5 py-2.5">Timestamp</th>
                      <th className="px-3 py-2.5">Severity</th>
                      <th className="px-3 py-2.5">Event Source</th>
                      <th className="px-3 py-2.5">Category</th>
                      <th className="px-3 py-2.5">Description</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredEvents.map((ev, i) => (
                      <tr key={i} className="hover:bg-slate-900/40">
                        <td className="px-3.5 py-2 text-slate-400 whitespace-nowrap">
                          {new Date(ev.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="px-3 py-2">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            ev.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                            ev.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                            ev.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400' :
                            'bg-slate-800 text-slate-400'
                          }`}>
                            {ev.severity}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-cyan-300 font-semibold">{ev.source}</td>
                        <td className="px-3 py-2 text-slate-400 uppercase">{ev.event_type}</td>
                        <td className="px-3 py-2 text-slate-300 truncate max-w-md">{ev.description}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ================= TAB 5: INVENTORY & PERSISTENCE ================= */}
          {activeTab === 'inventory' && (
            <div className="space-y-4">
              {/* Sub-nav */}
              <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
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
                  onClick={() => setInventorySubTab('startup')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
                    inventorySubTab === 'startup'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Startup Items ({startup.length})
                </button>
              </div>

              {/* Sub-content: Software */}
              {inventorySubTab === 'software' && (
                <div className="space-y-3">
                  <div className="relative max-w-md">
                    <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                    <input
                      type="text"
                      value={softwareSearch}
                      onChange={(e) => setSoftwareSearch(e.target.value)}
                      placeholder="Search installed applications..."
                      className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700/80 text-xs font-mono text-slate-200"
                    />
                  </div>

                  <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[450px] overflow-y-auto">
                    <table className="w-full text-xs font-mono text-left">
                      <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 sticky top-0 z-10 backdrop-blur-sm">
                        <tr>
                          <th className="px-3.5 py-2.5">Application</th>
                          <th className="px-3 py-2.5">Version</th>
                          <th className="px-3 py-2.5">Publisher</th>
                          <th className="px-3 py-2.5">Architecture</th>
                          <th className="px-3 py-2.5">Security Status</th>
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
                </div>
              )}

              {/* Sub-content: Services */}
              {inventorySubTab === 'services' && (
                <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[450px] overflow-y-auto">
                  <table className="w-full text-xs font-mono text-left">
                    <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 sticky top-0 z-10 backdrop-blur-sm">
                      <tr>
                        <th className="px-3.5 py-2.5">Service Name</th>
                        <th className="px-3 py-2.5">Display Name</th>
                        <th className="px-3 py-2.5">State</th>
                        <th className="px-3 py-2.5">Startup Type</th>
                        <th className="px-3 py-2.5">Binary Path</th>
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

              {/* Sub-content: Startup */}
              {inventorySubTab === 'startup' && (
                <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[450px] overflow-y-auto">
                  <table className="w-full text-xs font-mono text-left">
                    <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 sticky top-0 z-10 backdrop-blur-sm">
                      <tr>
                        <th className="px-3.5 py-2.5">Startup Item</th>
                        <th className="px-3 py-2.5">Persistence Source</th>
                        <th className="px-3 py-2.5">Execution Target</th>
                        <th className="px-3 py-2.5">Risk Flag</th>
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
                              <span className="px-2 py-0.5 rounded text-[10px] bg-red-500/20 text-red-400 border border-red-500/40 font-bold">
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
            </div>
          )}

          {/* ================= TAB 6: FILE SECURITY ================= */}
          {activeTab === 'files' && (
            <div className="space-y-4">
              <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono">
                <span className="text-slate-400 block mb-1">Monitored Watch Directories:</span>
                <span className="text-cyan-400 font-bold">
                  Downloads Folder, User Startup Folder, AppData Temp
                </span>
              </div>

              {/* File Change Events */}
              <div>
                <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold mb-2">
                  Recent File Modification Events
                </h4>
                {fileEvents.length === 0 ? (
                  <p className="text-xs font-mono text-slate-500 p-3 rounded-lg bg-slate-900/30 border border-slate-800">
                    No recent file creations or modifications detected in monitored folders.
                  </p>
                ) : (
                  <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[300px] overflow-y-auto">
                    <table className="w-full text-xs font-mono text-left">
                      <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                        <tr>
                          <th className="px-3 py-2">Event</th>
                          <th className="px-3 py-2">Filename</th>
                          <th className="px-3 py-2">Path</th>
                          <th className="px-3 py-2">SHA-256</th>
                          <th className="px-3 py-2">Time</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {fileEvents.map((fe, i) => (
                          <tr key={i} className="hover:bg-slate-900/40">
                            <td className="px-3 py-2">
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                fe.event_type === 'file_created' ? 'bg-cyan-500/20 text-cyan-300' :
                                fe.event_type === 'file_modified' ? 'bg-amber-500/20 text-amber-300' :
                                'bg-red-500/20 text-red-300'
                              }`}>
                                {fe.event_type}
                              </span>
                            </td>
                            <td className="px-3 py-2 font-bold text-white">{fe.filename}</td>
                            <td className="px-3 py-2 text-slate-400 truncate max-w-xs">{fe.path}</td>
                            <td className="px-3 py-2 text-slate-300 truncate max-w-xs font-mono">{fe.sha256 || 'N/A'}</td>
                            <td className="px-3 py-2 text-slate-400">{new Date(fe.timestamp).toLocaleTimeString()}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Monitored Executables Inventory */}
              <div>
                <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold mb-2">
                  Tracked Files with Computed Hashes
                </h4>
                <div className="border border-slate-800 rounded-lg overflow-x-auto max-h-[300px] overflow-y-auto">
                  <table className="w-full text-xs font-mono text-left">
                    <thead className="bg-slate-900 text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="px-3 py-2">Filename</th>
                        <th className="px-3 py-2">Size</th>
                        <th className="px-3 py-2">SHA-256 Hash</th>
                        <th className="px-3 py-2">Last Modified</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {trackedFiles.map((tf, i) => (
                        <tr key={i} className="hover:bg-slate-900/40">
                          <td className="px-3 py-2 font-bold text-slate-200">{tf.name}</td>
                          <td className="px-3 py-2 text-slate-400">{(tf.size / 1024).toFixed(1)} KB</td>
                          <td className="px-3 py-2 text-cyan-400 truncate max-w-sm select-all font-mono">
                            {tf.sha256 || 'Non-executable'}
                          </td>
                          <td className="px-3 py-2 text-slate-400">{tf.last_modified ? new Date(tf.last_modified).toLocaleString() : '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

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
