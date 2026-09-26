import React from 'react';
import { MailWarning, UserCheck, Activity, ShieldAlert } from 'lucide-react';

interface ThreatBadgeProps {
  type: string;
}

export const ThreatBadge: React.FC<ThreatBadgeProps> = ({ type }) => {
  const norm = type.toLowerCase();

  if (norm.includes('phish')) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-red-500/10 text-red-300 border border-red-500/30">
        <MailWarning className="w-3 h-3 text-red-400" />
        Phishing
      </span>
    );
  }

  if (norm.includes('deepfake')) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-purple-500/10 text-purple-300 border border-purple-500/30">
        <UserCheck className="w-3 h-3 text-purple-400" />
        Deepfake
      </span>
    );
  }

  if (norm.includes('account') || norm.includes('behavior') || norm.includes('login')) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-amber-500/10 text-amber-300 border border-amber-500/30">
        <Activity className="w-3 h-3 text-amber-400" />
        Account Takeover
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
      <ShieldAlert className="w-3 h-3 text-cyan-400" />
      {type}
    </span>
  );
};
