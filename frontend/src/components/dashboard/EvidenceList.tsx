import React from 'react';
import { EvidenceItem } from '../../types';
import { AlertCircle, CheckCircle2, ShieldAlert } from 'lucide-react';

interface EvidenceListProps {
  evidence: EvidenceItem[];
  title?: string;
}

export const EvidenceList: React.FC<EvidenceListProps> = ({
  evidence,
  title = 'Extracted Threat Indicators & Forensic Evidence'
}) => {
  if (!evidence || evidence.length === 0) {
    return (
      <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800 text-slate-400 text-xs font-mono flex items-center gap-2">
        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
        <span>No malicious forensic anomalies or threat heuristics flagged.</span>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-300 flex items-center gap-2">
          <ShieldAlert className="w-3.5 h-3.5 text-cyan-400" />
          <span>{title}</span>
        </h4>
        <span className="text-[10px] font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
          {evidence.length} INDICATORS DETECTED
        </span>
      </div>

      <div className="space-y-2">
        {evidence.map((item, idx) => (
          <div
            key={idx}
            className="p-3 rounded-lg bg-slate-900/80 border border-slate-800/90 hover:border-cyan-500/40 transition-all flex items-start justify-between gap-3 group"
          >
            <div className="flex items-start gap-2.5">
              <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-semibold text-cyan-300">
                    {item.indicator.replace(/_/g, ' ').toUpperCase()}
                  </span>
                </div>
                <p className="text-xs text-slate-300 mt-0.5 leading-relaxed">
                  {item.description}
                </p>
              </div>
            </div>

            {item.weight > 0 && (
              <span className="shrink-0 font-mono text-xs font-bold px-2 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30">
                +{item.weight} pts
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
