import React from 'react';

interface RiskScoreMeterProps {
  score: number;
  severity: string;
  size?: 'sm' | 'md' | 'lg';
}

export const RiskScoreMeter: React.FC<RiskScoreMeterProps> = ({ score, severity, size = 'md' }) => {
  const getScoreColor = (s: number) => {
    if (s >= 80) return { stroke: '#ef4444', text: 'text-red-400', glow: 'rgba(239, 68, 68, 0.4)' };
    if (s >= 60) return { stroke: '#f97316', text: 'text-orange-400', glow: 'rgba(249, 115, 22, 0.4)' };
    if (s >= 40) return { stroke: '#eab308', text: 'text-yellow-400', glow: 'rgba(234, 179, 8, 0.4)' };
    if (s >= 20) return { stroke: '#3b82f6', text: 'text-blue-400', glow: 'rgba(59, 130, 246, 0.4)' };
    return { stroke: '#10b981', text: 'text-emerald-400', glow: 'rgba(16, 185, 129, 0.4)' };
  };

  const { stroke, text, glow } = getScoreColor(score);

  const radius = size === 'lg' ? 44 : (size === 'md' ? 36 : 24);
  const strokeWidth = size === 'lg' ? 8 : (size === 'md' ? 6 : 4);
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;
  const dim = (radius + strokeWidth) * 2;

  return (
    <div className="flex flex-col items-center justify-center relative">
      <div className="relative flex items-center justify-center">
        <svg width={dim} height={dim} className="transform -rotate-90">
          {/* Background circle */}
          <circle
            cx={radius + strokeWidth}
            cy={radius + strokeWidth}
            r={radius}
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Active progress circle */}
          <circle
            cx={radius + strokeWidth}
            cy={radius + strokeWidth}
            r={radius}
            stroke={stroke}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            style={{
              filter: `drop-shadow(0 0 6px ${glow})`,
              transition: 'stroke-dashoffset 0.8s ease-in-out, stroke 0.5s ease'
            }}
          />
        </svg>
        
        {/* Center label */}
        <div className="absolute flex flex-col items-center justify-center font-mono">
          <span className={`font-bold ${size === 'lg' ? 'text-2xl' : (size === 'md' ? 'text-xl' : 'text-sm')} ${text}`}>
            {score}
          </span>
          {size !== 'sm' && (
            <span className="text-[9px] text-slate-400 tracking-wider">/100</span>
          )}
        </div>
      </div>

      {size !== 'sm' && (
        <span className={`mt-1 font-mono font-bold text-xs uppercase tracking-wider ${text}`}>
          {severity}
        </span>
      )}
    </div>
  );
};
