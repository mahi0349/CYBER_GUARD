import React from 'react';
import {
  LayoutDashboard,
  ScanLine,
  MailWarning,
  UserCheck,
  Activity,
  ShieldAlert,
  BarChart3,
  Sliders
} from 'lucide-react';

interface SidebarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab }) => {
  const navItems = [
    { id: 'dashboard', label: 'Command Center', icon: LayoutDashboard, badge: 'Live' },
    { id: 'scanner', label: 'Threat Scanner', icon: ScanLine, badge: 'Omni' },
    { id: 'phishing', label: 'Phishing Detector', icon: MailWarning, badge: 'ML 96%' },
    { id: 'deepfake', label: 'Deepfake & Media', icon: UserCheck, badge: 'Vision' },
    { id: 'behavior', label: 'Behavior / ATO', icon: Activity, badge: 'IsoForest' },
    { id: 'incidents', label: 'Incidents & Contain', icon: ShieldAlert, badge: 'MITRE' },
    { id: 'analytics', label: 'Model Benchmarks', icon: BarChart3 },
    { id: 'settings', label: 'Risk Policy', icon: Sliders },
  ];

  return (
    <aside className="w-64 border-r border-slate-800/80 bg-[#070a12]/95 flex flex-col justify-between p-4 shrink-0 h-full overflow-hidden select-none">
      <div className="space-y-6">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-slate-400 px-3 mb-2 font-semibold">
            Threat Modules
          </div>
          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectTab(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all group ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-500/20 to-blue-500/10 text-cyan-300 border border-cyan-500/40 shadow-sm shadow-cyan-500/10'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Icon className={`w-4 h-4 transition-colors ${isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-slate-300'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded border ${
                      isActive
                        ? 'bg-cyan-500/30 text-cyan-200 border-cyan-400/40'
                        : 'bg-slate-800/60 text-slate-400 border-slate-700/50'
                    }`}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>


      </div>

      {/* Footer System Spec */}
      <div className="pt-4 border-t border-slate-800/60 text-[10px] font-mono text-slate-400 space-y-1">
        <div className="flex justify-between">
          <span>PIPELINE</span>
          <span className="text-emerald-400">OPTIMAL</span>
        </div>
        <div className="flex justify-between">
          <span>RISK POLICY</span>
          <span className="text-cyan-400">DETERMINISTIC</span>
        </div>
        <div className="flex justify-between">
          <span>EXPLAINER</span>
          <span className="text-purple-400">GEMINI AI</span>
        </div>
      </div>
    </aside>
  );
};
