import React from 'react';
import { X, ShieldAlert, CheckCircle, AlertTriangle, ArrowRight, FileText } from 'lucide-react';
import { ThreatAlert } from '../../types/commandCenter';

interface AlertModalProps {
  alert: ThreatAlert | null;
  onClose: () => void;
}

export const AlertModal: React.FC<AlertModalProps> = ({ alert, onClose }) => {
  if (!alert) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-[#0b101d] border border-red-500/40 rounded-xl w-full max-w-2xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg border ${
              alert.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border-red-500/40' :
              alert.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border-orange-500/40' :
              'bg-amber-500/20 text-amber-400 border-amber-500/40'
            }`}>
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase font-bold ${
                  alert.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border-red-500/40' :
                  alert.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400 border-orange-500/40' :
                  'bg-amber-500/20 text-amber-400 border-amber-500/40'
                }`}>
                  {alert.severity}
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  {new Date(alert.created_at).toLocaleTimeString()}
                </span>
              </div>
              <h3 className="text-sm font-bold text-white font-mono mt-0.5">{alert.title}</h3>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto space-y-5 text-xs font-mono">
          {/* Metadata */}
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-slate-400 block mb-1">Detection Source</span>
              <span className="text-cyan-400 font-bold">{alert.detection_source}</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
              <span className="text-slate-400 block mb-1">Category</span>
              <span className="text-slate-200 font-bold">{alert.category}</span>
            </div>
          </div>

          {/* Affected Object */}
          {alert.affected_object && (
            <div>
              <span className="text-slate-400 uppercase font-bold block mb-1">Affected System Object</span>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 break-all select-all">
                {alert.affected_object}
              </div>
            </div>
          )}

          {/* Evidence */}
          <div>
            <span className="text-slate-400 uppercase font-bold block mb-1">Telemetry Evidence</span>
            <div className="space-y-1.5">
              {alert.evidence && alert.evidence.length > 0 ? (
                alert.evidence.map((ev, i) => (
                  <div key={i} className="p-2.5 rounded bg-slate-900/80 border border-slate-800/80 flex items-start gap-2">
                    <span className="text-red-400 font-bold shrink-0">{ev.indicator}:</span>
                    <span className="text-slate-300 break-all">{ev.value}</span>
                  </div>
                ))
              ) : (
                <div className="text-slate-500 italic p-2">Standard heuristic rule match</div>
              )}
            </div>
          </div>

          {/* Explanation */}
          <div>
            <span className="text-slate-400 uppercase font-bold block mb-1">Technical Explanation</span>
            <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 text-slate-300 leading-relaxed">
              {alert.explanation}
            </div>
          </div>

          {/* Recommended Action */}
          <div className="p-4 rounded-lg bg-cyan-950/30 border border-cyan-500/30">
            <div className="flex items-center gap-2 text-cyan-300 font-bold mb-1.5">
              <ArrowRight className="w-4 h-4 text-cyan-400" />
              <span>DEFENSIVE REMEDIATION GUIDANCE</span>
            </div>
            <p className="text-slate-300 leading-relaxed">
              {alert.recommended_action}
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-900/80 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-200 transition-colors"
          >
            Close Alert
          </button>
        </div>
      </div>
    </div>
  );
};
