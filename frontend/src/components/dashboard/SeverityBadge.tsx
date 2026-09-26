import React from 'react';

interface SeverityBadgeProps {
  severity: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  size?: 'sm' | 'md' | 'lg';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'sm' }) => {
  const norm = severity.toUpperCase();
  
  const styles: Record<string, { bg: string; text: string; border: string; dot: string }> = {
    CRITICAL: {
      bg: 'bg-red-500/15',
      text: 'text-red-400',
      border: 'border-red-500/40',
      dot: 'bg-red-500'
    },
    HIGH: {
      bg: 'bg-orange-500/15',
      text: 'text-orange-400',
      border: 'border-orange-500/40',
      dot: 'bg-orange-500'
    },
    MEDIUM: {
      bg: 'bg-yellow-500/15',
      text: 'text-yellow-400',
      border: 'border-yellow-500/40',
      dot: 'bg-yellow-500'
    },
    LOW: {
      bg: 'bg-blue-500/15',
      text: 'text-blue-400',
      border: 'border-blue-500/40',
      dot: 'bg-blue-500'
    },
    SAFE: {
      bg: 'bg-emerald-500/15',
      text: 'text-emerald-400',
      border: 'border-emerald-500/40',
      dot: 'bg-emerald-500'
    }
  };

  const style = styles[norm] || styles.LOW;

  const sizeClass = size === 'lg' ? 'px-3 py-1 text-xs' : (size === 'md' ? 'px-2.5 py-0.5 text-xs' : 'px-2 py-0.5 text-[10px]');

  return (
    <span className={`inline-flex items-center gap-1.5 rounded font-mono font-semibold uppercase tracking-wider border ${style.bg} ${style.text} ${style.border} ${sizeClass}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${style.dot} ${norm === 'CRITICAL' ? 'animate-ping' : ''}`} />
      {norm}
    </span>
  );
};
