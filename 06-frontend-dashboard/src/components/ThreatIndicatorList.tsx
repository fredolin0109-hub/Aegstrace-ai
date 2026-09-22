import React, { useState } from 'react';
import { ThreatIndicatorItem } from '../types';
import SeverityBadge from './SeverityBadge';
import { ChevronDown, ChevronRight, ShieldAlert, Fingerprint } from 'lucide-react';

interface ThreatIndicatorListProps {
  indicators: ThreatIndicatorItem[];
  title?: string;
  className?: string;
}

export const ThreatIndicatorList: React.FC<ThreatIndicatorListProps> = ({
  indicators,
  title = 'Extracted Threat Indicators (IOCs)',
  className = '',
}) => {
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);

  const toggleExpand = (idx: number) => {
    setExpandedIndex(expandedIndex === idx ? null : idx);
  };

  if (!indicators || indicators.length === 0) {
    return (
      <div className={`rounded-xl bg-slate-900/80 border border-slate-800 p-6 text-center ${className}`}>
        <Fingerprint className="w-8 h-8 text-slate-600 mx-auto mb-2" />
        <p className="text-sm text-slate-400 font-mono">No active threat indicators identified.</p>
        <p className="text-xs text-slate-500 mt-1">URL exhibits baseline normal behavioral signatures.</p>
      </div>
    );
  }

  return (
    <div className={`rounded-xl bg-slate-900/80 border border-slate-800 p-5 ${className}`}>
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80 mb-4">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-amber-400" />
          <h4 className="text-sm font-semibold font-mono uppercase tracking-wider text-slate-200">
            {title}
          </h4>
        </div>
        <span className="text-xs font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800">
          {indicators.length} IOC{indicators.length === 1 ? '' : 's'}
        </span>
      </div>

      <div className="space-y-2">
        {indicators.map((indicator, idx) => {
          const isExpanded = expandedIndex === idx;
          const hasDetails = indicator.details && Object.keys(indicator.details).length > 0;

          return (
            <div
              key={idx}
              className="rounded-lg bg-slate-950/70 border border-slate-800/80 overflow-hidden transition-all duration-200"
            >
              <div
                onClick={() => hasDetails && toggleExpand(idx)}
                className={`p-3 flex items-center justify-between gap-3 text-xs font-mono ${
                  hasDetails ? 'cursor-pointer hover:bg-slate-900/60' : ''
                }`}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  {hasDetails ? (
                    isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-slate-400 flex-shrink-0" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-slate-400 flex-shrink-0" />
                    )
                  ) : (
                    <div className="w-4 flex-shrink-0" />
                  )}
                  <span className="text-slate-400 uppercase text-[11px] font-semibold tracking-wider">
                    [{indicator.indicator_type}]
                  </span>
                  <span className="text-slate-200 font-medium truncate" title={indicator.value}>
                    {indicator.value}
                  </span>
                </div>

                <div className="flex-shrink-0">
                  <SeverityBadge severity={indicator.severity} size="sm" />
                </div>
              </div>

              {isExpanded && hasDetails && (
                <div className="px-9 pb-3 pt-1 border-t border-slate-900 bg-slate-900/40 text-[11px] font-mono">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-400 pt-2">
                    {Object.entries(indicator.details).map(([k, v]) => (
                      <div key={k} className="p-1.5 rounded bg-slate-950/60 border border-slate-800/60">
                        <span className="text-slate-400 uppercase block text-[9px]">{k}:</span>
                        <span className="text-slate-200 block truncate">
                          {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ThreatIndicatorList;
