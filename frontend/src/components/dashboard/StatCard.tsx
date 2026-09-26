import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  change?: string;
  isPositive?: boolean;
  icon: LucideIcon;
  color?: 'cyan' | 'red' | 'amber' | 'emerald' | 'blue';
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  change,
  isPositive,
  icon: Icon,
  color = 'cyan',
}) => {
  const colorMap = {
    cyan: 'border-cyan-500/20 text-cyan-400 bg-cyan-500/10 shadow-cyan-500/10',
    red: 'border-red-500/30 text-red-400 bg-red-500/10 shadow-red-500/10',
    amber: 'border-amber-500/30 text-amber-400 bg-amber-500/10 shadow-amber-500/10',
    emerald: 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10 shadow-emerald-500/10',
    blue: 'border-blue-500/30 text-blue-400 bg-blue-500/10 shadow-blue-500/10',
  };

  return (
    <div className="cyber-panel rounded-xl p-4 relative overflow-hidden transition-all duration-300 hover:border-cyan-500/40">
      <div className="flex items-center justify-between">
        <span className="text-xs font-mono uppercase tracking-wider text-slate-400">{title}</span>
        <div className={`p-2 rounded-lg border ${colorMap[color]}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>

      <div className="mt-3 flex items-baseline justify-between">
        <div className="text-2xl font-bold font-mono text-white tracking-tight">{value}</div>
        {change && (
          <span className={`text-xs font-mono font-medium ${isPositive ? 'text-emerald-400' : 'text-red-400'}`}>
            {change}
          </span>
        )}
      </div>
      
      {/* Subtle corner light bar */}
      <div className="absolute bottom-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-500/30 to-transparent"></div>
    </div>
  );
};
