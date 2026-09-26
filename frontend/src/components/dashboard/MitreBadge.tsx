import React from 'react';
import { Crosshair } from 'lucide-react';

interface MitreBadgeProps {
  technique?: string;
  name?: string;
}

export const MitreBadge: React.FC<MitreBadgeProps> = ({ technique = 'T1566', name = 'Phishing' }) => {
  return (
    <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-slate-900 border border-slate-700/80 text-xs font-mono">
      <div className="flex items-center gap-1 text-cyan-400 font-bold">
        <Crosshair className="w-3.5 h-3.5" />
        <span>MITRE</span>
      </div>
      <span className="text-slate-400">|</span>
      <span className="text-white font-semibold">{technique}</span>
      {name && <span className="text-slate-400 text-[11px] hidden sm:inline font-sans">({name})</span>}
    </div>
  );
};
