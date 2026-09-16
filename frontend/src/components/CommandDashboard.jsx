import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Activity,
  AlertOctagon,
  Zap,
  RefreshCw,
  Clock,
  ExternalLink,
  Sliders,
  Filter,
  Search,
  CheckCircle2,
  Terminal,
  Crosshair,
  UserX,
  Globe,
  Radio,
  ChevronRight,
  Layers,
  Lock,
  Eye,
  AlertTriangle,
  Play
} from 'lucide-react';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  Legend
} from 'recharts';
import {
  fetchDashboardMetrics,
  fetchDashboardTimeline,
  fetchDashboardDistribution,
  fetchHighRiskEntities,
  fetchCorrelations,
  fetchEvents,
  fetchPlaybookCatalog,
  executePlaybookAction,
  updateIncidentStatus
} from '../api/client';

const SEVERITY_COLORS = {
  Safe: '#10b981',
  Low: '#3b82f6',
  Medium: '#f59e0b',
  High: '#f97316',
  Critical: '#ef4444'
};

const CATEGORY_COLORS = ['#06b6d4', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#6366f1'];

export default function CommandDashboard({ onNavigateScenario }) {
  const [metrics, setMetrics] = useState(null);
  const [timelineData, setTimelineData] = useState([]);
  const [distribution, setDistribution] = useState(null);
  const [entities, setEntities] = useState({ top_identities: [], top_ips: [] });
  const [correlations, setCorrelations] = useState([]);
  const [events, setEvents] = useState([]);
  const [playbookCatalog, setPlaybookCatalog] = useState({});
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedCategory, setSelectedCategory] = useState('ALL');

  // Interactive Modal states
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [playbookModalEvent, setPlaybookModalEvent] = useState(null);
  const [executingAction, setExecutingAction] = useState(false);
  const [executionResult, setExecutionResult] = useState(null);
  const [actionNotes, setActionNotes] = useState('');

  const loadDashboardData = async (isManual = false) => {
    if (isManual) setRefreshing(true);
    else setLoading(true);

    try {
      const [metricsRes, timelineRes, distRes, entitiesRes, corrRes, eventsRes, catalogRes] = await Promise.all([
        fetchDashboardMetrics().catch(() => null),
        fetchDashboardTimeline(30).catch(() => []),
        fetchDashboardDistribution().catch(() => null),
        fetchHighRiskEntities().catch(() => ({ top_identities: [], top_ips: [] })),
        fetchCorrelations().catch(() => []),
        fetchEvents(50).catch(() => []),
        fetchPlaybookCatalog().catch(() => ({}))
      ]);

      setMetrics(metricsRes);
      setTimelineData(
        (timelineRes || []).map((t, idx) => ({
          name: t.timestamp ? new Date(t.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : `#${idx + 1}`,
          riskScore: t.risk_score || 0,
          category: t.category || 'Threat',
          classification: t.threat_classification || 'Alert'
        }))
      );
      setDistribution(distRes);
      setEntities(entitiesRes || { top_identities: [], top_ips: [] });
      setCorrelations(corrRes || []);
      setEvents(eventsRes || []);
      setPlaybookCatalog(catalogRes || {});
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadDashboardData();
    const interval = setInterval(() => loadDashboardData(true), 30000);
    return () => clearInterval(interval);
  }, []);

  const handleExecutePlaybook = async (actionKey) => {
    if (!playbookModalEvent) return;
    setExecutingAction(true);
    setExecutionResult(null);
    try {
      const res = await executePlaybookAction({
        event_id: playbookModalEvent.id,
        action_key: actionKey,
        operator: 'Lead SOC Analyst (Console)',
        notes: actionNotes || 'Automated containment response triggered from SOC Command.'
      });
      setExecutionResult(res);
      // Refresh events and metrics
      loadDashboardData(true);
    } catch (err) {
      alert('Playbook execution failed: ' + err.message);
    } finally {
      setExecutingAction(false);
    }
  };

  const handleStatusChange = async (eventId, newStatus) => {
    try {
      await updateIncidentStatus({ event_id: eventId, status: newStatus });
      loadDashboardData(true);
    } catch (err) {
      alert('Status update failed: ' + err.message);
    }
  };

  // Filtered Events
  const filteredEvents = events.filter((ev) => {
    const matchesSeverity = selectedSeverity === 'ALL' || ev.risk_level === selectedSeverity;
    const matchesCategory = selectedCategory === 'ALL' || ev.category === selectedCategory;
    const matchesSearch =
      !searchQuery ||
      ev.threat_classification?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ev.target_identity?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ev.origin_ip?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ev.human_explanation?.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSeverity && matchesCategory && matchesSearch;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* SOC Command Header */}
      <div
        className="cyber-card"
        style={{
          padding: '20px 24px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '16px',
          borderLeft: '4px solid var(--accent-cyan)'
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '1.4rem', fontWeight: 800, letterSpacing: '-0.02em' }}>
              CYBERGUARD SOC Command Center
            </h1>
            <span className="badge badge-safe" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
              <Radio size={10} className="animate-spin" /> REAL-TIME INGESTION ACTIVE
            </span>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Unified cross-module risk correlation, automated MITRE ATT&CK mitigation & incident response telemetry.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button
            onClick={() => loadDashboardData(true)}
            disabled={refreshing}
            className="btn-cyber-primary"
            style={{ padding: '8px 16px', fontSize: '0.8rem' }}
          >
            <RefreshCw size={14} className={refreshing ? 'animate-spin' : ''} />
            {refreshing ? 'Syncing...' : 'Sync Telemetry'}
          </button>
        </div>
      </div>

      {/* 4 High-Impact KPI Metrics Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
        {/* Card 1: Total Events */}
        <div className="cyber-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
                Total Analyzed Events
              </p>
              <h2 style={{ fontSize: '2rem', fontWeight: 800, marginTop: '4px', color: '#ffffff' }}>
                {metrics?.total_events || events.length || 0}
              </h2>
            </div>
            <div style={{ padding: '10px', borderRadius: '10px', backgroundColor: 'rgba(6, 182, 212, 0.1)', color: 'var(--accent-cyan)' }}>
              <Layers size={22} />
            </div>
          </div>
          <div style={{ marginTop: '12px', display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            <Activity size={14} color="#06b6d4" /> Across Phishing, Deepfake & ATO sensors
          </div>
        </div>

        {/* Card 2: Critical & High Threats */}
        <div className="cyber-card" style={{ padding: '20px', borderTop: '2px solid var(--risk-critical)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
                Critical & High Threats
              </p>
              <h2 style={{ fontSize: '2rem', fontWeight: 800, marginTop: '4px', color: '#ef4444' }}>
                {metrics?.critical_high_threats || events.filter(e => e.risk_level === 'Critical' || e.risk_level === 'High').length || 0}
              </h2>
            </div>
            <div style={{ padding: '10px', borderRadius: '10px', backgroundColor: 'rgba(239, 68, 68, 0.12)', color: '#ef4444' }}>
              <ShieldAlert size={22} />
            </div>
          </div>
          <div style={{ marginTop: '12px', display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: '#ef4444' }}>
            <AlertOctagon size={14} /> Immediate containment required
          </div>
        </div>

        {/* Card 3: Mean Risk Score */}
        <div className="cyber-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
                Normalized Threat Score
              </p>
              <h2 style={{ fontSize: '2rem', fontWeight: 800, marginTop: '4px', color: '#f59e0b' }}>
                {metrics?.avg_risk_score ?? 0} <span style={{ fontSize: '1rem', color: 'var(--text-muted)' }}>/ 100</span>
              </h2>
            </div>
            <div style={{ padding: '10px', borderRadius: '10px', backgroundColor: 'rgba(245, 158, 11, 0.1)', color: '#f59e0b' }}>
              <Sliders size={22} />
            </div>
          </div>
          <div style={{ marginTop: '12px' }}>
            <div style={{ height: '6px', width: '100%', backgroundColor: 'rgba(255, 255, 255, 0.08)', borderRadius: '9999px', overflow: 'hidden' }}>
              <div
                style={{
                  height: '100%',
                  width: `${metrics?.avg_risk_score || 0}%`,
                  background: 'linear-gradient(90deg, #10b981, #f59e0b, #ef4444)'
                }}
              />
            </div>
          </div>
        </div>

        {/* Card 4: Containment Efficiency */}
        <div className="cyber-card" style={{ padding: '20px', borderTop: '2px solid var(--risk-safe)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
                Automated Containment Rate
              </p>
              <h2 style={{ fontSize: '2rem', fontWeight: 800, marginTop: '4px', color: '#10b981' }}>
                {metrics?.containment_rate ?? 100}%
              </h2>
            </div>
            <div style={{ padding: '10px', borderRadius: '10px', backgroundColor: 'rgba(16, 185, 129, 0.1)', color: '#10b981' }}>
              <ShieldCheck size={22} />
            </div>
          </div>
          <div style={{ marginTop: '12px', display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: '#34d399' }}>
            <CheckCircle2 size={14} /> {metrics?.total_remediations || 0} Playbook actions executed
          </div>
        </div>
      </div>

      {/* Multi-Stage Threat Correlation Alert Banner (if correlations detected) */}
      {correlations.length > 0 && (
        <div
          className="cyber-card"
          style={{
            padding: '16px 20px',
            backgroundColor: 'rgba(239, 68, 68, 0.08)',
            border: '1px solid rgba(239, 68, 68, 0.35)',
            display: 'flex',
            flexDirection: 'column',
            gap: '10px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertTriangle size={18} color="#ef4444" />
            <span style={{ fontSize: '0.9rem', fontWeight: 700, color: '#f87171' }}>
              CROSS-MODULE CORRELATION: {correlations.length} Multi-Stage Attack Campaign(s) Active
            </span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '12px' }}>
            {correlations.map((corr, idx) => (
              <div
                key={idx}
                style={{
                  backgroundColor: 'rgba(15, 23, 42, 0.8)',
                  padding: '12px 14px',
                  borderRadius: '8px',
                  border: '1px solid rgba(239, 68, 68, 0.2)'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontWeight: 700, fontSize: '0.8rem', color: '#ef4444' }}>
                    {corr.correlation_type}
                  </span>
                  <span className="badge badge-critical" style={{ fontSize: '0.65rem' }}>
                    Score: {corr.composite_risk_score}
                  </span>
                </div>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  {corr.summary}
                </p>
                <div style={{ marginTop: '8px', fontSize: '0.72rem', color: '#38bdf8', fontWeight: 600 }}>
                  👉 Recommended: {corr.recommended_response}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Visual Telemetry Grid: Attack Timeline & Distributions */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(460px, 1fr))', gap: '20px' }}>
        {/* Timeline AreaChart */}
        <div className="cyber-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div>
              <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>Attack Velocity & Risk Timeline</h3>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Event chronometry with normalized threat scores</p>
            </div>
            <Clock size={16} color="var(--accent-cyan)" />
          </div>

          <div style={{ height: '240px', width: '100%' }}>
            {timelineData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6} />
                      <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                  <YAxis stroke="#64748b" fontSize={11} domain={[0, 100]} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px', fontSize: '0.75rem' }}
                  />
                  <Area type="monotone" dataKey="riskScore" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#riskGradient)" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                Awaiting telemetry events... Run detection scenarios to populate.
              </div>
            )}
          </div>
        </div>

        {/* Category Breakdown & Severity */}
        <div className="cyber-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div>
              <h3 style={{ fontSize: '1rem', fontWeight: 700 }}>Threat Vector & Severity Breakdown</h3>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Proportion by category and severity tiers</p>
            </div>
            <Crosshair size={16} color="var(--accent-cyan)" />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', height: '240px' }}>
            {/* Category Donut */}
            <div>
              <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textAlign: 'center', marginBottom: '8px' }}>By Vector</p>
              {distribution?.categories?.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <PieChart>
                    <Pie
                      data={distribution.categories}
                      dataKey="count"
                      nameKey="category"
                      cx="50%"
                      cy="50%"
                      innerRadius={42}
                      outerRadius={65}
                      paddingAngle={3}
                    >
                      {distribution.categories.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={CATEGORY_COLORS[index % CATEGORY_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px', fontSize: '0.72rem' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ height: '180px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                  No vector data
                </div>
              )}
            </div>

            {/* Severity Bars */}
            <div>
              <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textAlign: 'center', marginBottom: '8px' }}>By Severity</p>
              {distribution?.risk_levels?.length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={distribution.risk_levels} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis dataKey="level" stroke="#64748b" fontSize={10} />
                    <YAxis stroke="#64748b" fontSize={10} allowDecimals={false} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px', fontSize: '0.72rem' }}
                    />
                    <Bar dataKey="count">
                      {distribution.risk_levels.map((entry, index) => (
                        <Cell key={`bar-${index}`} fill={entry.color || SEVERITY_COLORS[entry.level] || '#06b6d4'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div style={{ height: '180px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                  No severity data
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* High-Risk Adversary & Identity Intelligence */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '20px' }}>
        {/* Top Targeted Identities */}
        <div className="cyber-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
            <UserX size={16} color="#ef4444" />
            <h3 style={{ fontSize: '0.95rem', fontWeight: 700 }}>Most-Targeted User Identities</h3>
          </div>
          {entities.top_identities.length === 0 ? (
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No targeted users recorded yet.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {entities.top_identities.slice(0, 5).map((id, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '8px 12px',
                    borderRadius: '8px',
                    backgroundColor: 'rgba(255, 255, 255, 0.03)',
                    border: '1px solid var(--border-subtle)'
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '0.82rem' }}>{id.entity}</div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                      {id.total_incidents} attacks · Peak: {id.peak_risk_score}
                    </div>
                  </div>
                  <span className={`badge badge-${id.risk_level.toLowerCase()}`} style={{ fontSize: '0.7rem' }}>
                    {id.risk_level} ({id.composite_risk_score})
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top Malicious Origin IPs */}
        <div className="cyber-card" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
            <Globe size={16} color="#f97316" />
            <h3 style={{ fontSize: '0.95rem', fontWeight: 700 }}>Hostile Origin IPs</h3>
          </div>
          {entities.top_ips.length === 0 ? (
            <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No hostile origin IPs recorded yet.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {entities.top_ips.slice(0, 5).map((ip, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '8px 12px',
                    borderRadius: '8px',
                    backgroundColor: 'rgba(255, 255, 255, 0.03)',
                    border: '1px solid var(--border-subtle)'
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '0.82rem', fontFamily: 'var(--font-mono)' }}>{ip.entity}</div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                      {ip.total_incidents} incident hits · MITRE: {ip.mitre_techniques?.join(', ') || 'N/A'}
                    </div>
                  </div>
                  <span className={`badge badge-${ip.risk_level.toLowerCase()}`} style={{ fontSize: '0.7rem' }}>
                    {ip.risk_level} ({ip.composite_risk_score})
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Live Threat Incident Feed & Playbook Containment Console */}
      <div className="cyber-card" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px', marginBottom: '18px' }}>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 800 }}>SOC Incident Command Feed</h3>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              Real-time threat events with one-click automated playbook containment
            </p>
          </div>

          {/* Search and Filters */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <div style={{ position: 'relative' }}>
              <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search user, IP, rule..."
                style={{
                  padding: '6px 12px 6px 30px',
                  borderRadius: '6px',
                  backgroundColor: 'rgba(15, 23, 42, 0.6)',
                  border: '1px solid var(--border-subtle)',
                  color: '#ffffff',
                  fontSize: '0.78rem'
                }}
              />
            </div>

            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              style={{
                padding: '6px 10px',
                borderRadius: '6px',
                backgroundColor: 'rgba(15, 23, 42, 0.6)',
                border: '1px solid var(--border-subtle)',
                color: '#ffffff',
                fontSize: '0.78rem'
              }}
            >
              <option value="ALL">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
              <option value="Safe">Safe</option>
            </select>
          </div>
        </div>

        {/* Incidents Table */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)', textAlign: 'left' }}>
                <th style={{ padding: '10px 12px' }}>Timestamp</th>
                <th style={{ padding: '10px 12px' }}>Source / Category</th>
                <th style={{ padding: '10px 12px' }}>Threat Classification</th>
                <th style={{ padding: '10px 12px' }}>Target / Origin</th>
                <th style={{ padding: '10px 12px' }}>Risk Score</th>
                <th style={{ padding: '10px 12px' }}>Status</th>
                <th style={{ padding: '10px 12px', textAlign: 'right' }}>Containment Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan="7" style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                    No threat events matching filter criteria.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((ev) => (
                  <tr
                    key={ev.id}
                    style={{
                      borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                      transition: 'background 0.15s',
                    }}
                    className="hover:bg-slate-900"
                  >
                    <td style={{ padding: '12px', whiteSpace: 'nowrap', color: 'var(--text-secondary)' }}>
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Just now'}
                    </td>
                    <td style={{ padding: '12px' }}>
                      <div style={{ fontWeight: 600 }}>{ev.category}</div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{ev.source}</div>
                    </td>
                    <td style={{ padding: '12px' }}>
                      <div style={{ fontWeight: 600, color: '#ffffff' }}>{ev.threat_classification}</div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {ev.human_explanation}
                      </div>
                    </td>
                    <td style={{ padding: '12px' }}>
                      <div style={{ fontSize: '0.78rem' }}>{ev.target_identity || 'N/A'}</div>
                      <div style={{ fontSize: '0.7rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                        {ev.origin_ip || 'Internal'}
                      </div>
                    </td>
                    <td style={{ padding: '12px' }}>
                      <span className={`badge badge-${ev.risk_level?.toLowerCase() || 'safe'}`}>
                        {ev.risk_score} · {ev.risk_level}
                      </span>
                    </td>
                    <td style={{ padding: '12px' }}>
                      <select
                        value={ev.incident_status || 'Detected'}
                        onChange={(e) => handleStatusChange(ev.id, e.target.value)}
                        style={{
                          padding: '3px 6px',
                          borderRadius: '4px',
                          backgroundColor: ev.incident_status === 'Mitigated' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(255, 255, 255, 0.05)',
                          color: ev.incident_status === 'Mitigated' ? '#34d399' : 'var(--text-secondary)',
                          border: '1px solid var(--border-subtle)',
                          fontSize: '0.72rem'
                        }}
                      >
                        <option value="Detected">Detected</option>
                        <option value="Investigating">Investigating</option>
                        <option value="Mitigated">Mitigated</option>
                        <option value="Resolved">Resolved</option>
                        <option value="False Positive">False Positive</option>
                      </select>
                    </td>
                    <td style={{ padding: '12px', textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: '6px' }}>
                        <button
                          onClick={() => {
                            setPlaybookModalEvent(ev);
                            setExecutionResult(null);
                          }}
                          className="btn-cyber-primary"
                          style={{ padding: '5px 10px', fontSize: '0.72rem' }}
                        >
                          <Play size={11} /> Playbook
                        </button>
                        <button
                          onClick={() => setSelectedEvent(ev)}
                          className="btn-cyber-secondary"
                          style={{ padding: '5px 10px', fontSize: '0.72rem' }}
                        >
                          <Eye size={11} /> Forensic
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Playbook Execution Modal */}
      {playbookModalEvent && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(8px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 100,
            padding: '20px'
          }}
        >
          <div
            className="cyber-card"
            style={{
              maxWidth: '680px',
              width: '100%',
              padding: '28px',
              backgroundColor: '#0a0f1d',
              border: '1px solid var(--border-active)',
              boxShadow: '0 20px 50px rgba(0,0,0,0.8)',
              display: 'flex',
              flexDirection: 'column',
              gap: '16px'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h2 style={{ fontSize: '1.25rem', fontWeight: 800 }}>Execute Containment Playbook</h2>
                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                  Target: {playbookModalEvent.threat_classification} ({playbookModalEvent.id.slice(0, 8)})
                </p>
              </div>
              <button
                onClick={() => setPlaybookModalEvent(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '1.2rem' }}
              >
                ✕
              </button>
            </div>

            {/* Incident Summary */}
            <div
              style={{
                padding: '12px',
                borderRadius: '8px',
                backgroundColor: 'rgba(255, 255, 255, 0.03)',
                border: '1px solid var(--border-subtle)',
                fontSize: '0.8rem'
              }}
            >
              <div><strong>Target:</strong> {playbookModalEvent.target_identity || 'N/A'} | <strong>Origin IP:</strong> {playbookModalEvent.origin_ip || 'N/A'}</div>
              <div style={{ color: 'var(--text-secondary)', marginTop: '4px' }}>{playbookModalEvent.human_explanation}</div>
            </div>

            {/* Playbook Options */}
            <div>
              <p style={{ fontSize: '0.82rem', fontWeight: 600, marginBottom: '10px', color: 'var(--accent-cyan)' }}>
                Select Response Playbook Action:
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '10px' }}>
                {Object.entries(playbookCatalog).map(([key, item]) => (
                  <button
                    key={key}
                    onClick={() => handleExecutePlaybook(key)}
                    disabled={executingAction}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'flex-start',
                      padding: '10px 12px',
                      borderRadius: '8px',
                      backgroundColor: 'rgba(15, 23, 42, 0.9)',
                      border: '1px solid var(--border-subtle)',
                      color: '#ffffff',
                      textAlign: 'left',
                      cursor: 'pointer',
                      transition: 'all 0.2s'
                    }}
                    onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'var(--accent-cyan)')}
                    onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'var(--border-subtle)')}
                  >
                    <span style={{ fontWeight: 700, fontSize: '0.8rem', color: '#38bdf8' }}>{item.title}</span>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '2px', lineHeight: 1.3 }}>
                      {item.description}
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {/* Execution Result Log */}
            {executionResult && (
              <div
                style={{
                  padding: '14px',
                  borderRadius: '8px',
                  backgroundColor: 'rgba(16, 185, 129, 0.08)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  fontSize: '0.78rem'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#34d399', fontWeight: 700 }}>
                  <CheckCircle2 size={16} /> {executionResult.message}
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', backgroundColor: '#000', padding: '8px', borderRadius: '6px', marginTop: '8px', color: '#a7f3d0' }}>
                  $ {executionResult.action?.simulated_command}
                </div>
                <div style={{ marginTop: '6px', fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
                  Audit verification: {executionResult.action?.audit_verification} · Incident marked as <strong>Mitigated</strong>.
                </div>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '8px' }}>
              <button onClick={() => setPlaybookModalEvent(null)} className="btn-cyber-secondary">
                Close Console
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Forensic Detail Modal */}
      {selectedEvent && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(8px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 100,
            padding: '20px'
          }}
        >
          <div
            className="cyber-card"
            style={{
              maxWidth: '750px',
              width: '100%',
              maxHeight: '90vh',
              overflowY: 'auto',
              padding: '28px',
              backgroundColor: '#0a0f1d',
              border: '1px solid var(--border-active)',
              display: 'flex',
              flexDirection: 'column',
              gap: '16px'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <span className={`badge badge-${selectedEvent.risk_level?.toLowerCase() || 'safe'}`}>
                  {selectedEvent.risk_level} · Score: {selectedEvent.risk_score}
                </span>
                <h2 style={{ fontSize: '1.25rem', fontWeight: 800, marginTop: '6px' }}>
                  {selectedEvent.threat_classification}
                </h2>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: '1.2rem' }}
              >
                ✕
              </button>
            </div>

            <div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                {selectedEvent.human_explanation}
              </p>
            </div>

            {/* MITRE ATT&CK */}
            {selectedEvent.mitre_attack_techniques?.length > 0 && (
              <div>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '6px', color: 'var(--accent-cyan)' }}>
                  MITRE ATT&CK Mapping
                </h4>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                  {selectedEvent.mitre_attack_techniques.map((t, idx) => (
                    <span key={idx} className="badge" style={{ backgroundColor: 'rgba(139, 92, 246, 0.2)', color: '#c084fc', border: '1px solid rgba(139, 92, 246, 0.4)' }}>
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Indicators */}
            {selectedEvent.indicators?.length > 0 && (
              <div>
                <h4 style={{ fontSize: '0.85rem', fontWeight: 700, marginBottom: '6px' }}>
                  Extracted Threat Indicators ({selectedEvent.indicators.length})
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {selectedEvent.indicators.map((ind, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '8px 12px',
                        borderRadius: '6px',
                        backgroundColor: 'rgba(255, 255, 255, 0.03)',
                        border: '1px solid var(--border-subtle)',
                        fontSize: '0.78rem',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center'
                      }}
                    >
                      <div>
                        <strong>{ind.name}</strong>: {ind.description}
                      </div>
                      <span style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>w={ind.weight}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '12px' }}>
              <button onClick={() => setSelectedEvent(null)} className="btn-cyber-secondary">
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
