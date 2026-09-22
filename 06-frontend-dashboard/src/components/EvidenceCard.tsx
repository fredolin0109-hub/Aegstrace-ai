import React, { useState } from 'react';
import { ShieldAlert, Cpu, Network, Check, Copy } from 'lucide-react';

interface EvidenceCardProps {
  title: string;
  category: 'AIML' | 'DSA' | 'INTEL' | 'NETWORK' | 'GENERAL';
  data: Record<string, any> | string[] | string;
  className?: string;
}

export const EvidenceCard: React.FC<EvidenceCardProps> = ({
  title,
  category,
  data,
  className = '',
}) => {
  const [copied, setCopied] = useState(false);

  const copyToClipboard = () => {
    const text = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getCategoryIcon = () => {
    switch (category) {
      case 'AIML':
        return <Cpu className="w-4 h-4 text-cyan-400" />;
      case 'DSA':
        return <Network className="w-4 h-4 text-emerald-400" />;
      case 'INTEL':
        return <ShieldAlert className="w-4 h-4 text-amber-400" />;
      default:
        return <Network className="w-4 h-4 text-slate-400" />;
    }
  };

  return (
    <div className={`rounded-xl bg-slate-900/80 border border-slate-800 p-5 ${className}`}>
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-md bg-slate-800 border border-slate-700">
            {getCategoryIcon()}
          </div>
          <div>
            <h4 className="text-sm font-semibold text-slate-200">{title}</h4>
            <span className="text-[10px] font-mono tracking-widest text-slate-500 uppercase">
              CATEGORY: {category}
            </span>
          </div>
        </div>
        <button
          onClick={copyToClipboard}
          title="Copy to clipboard"
          className="p-1.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-slate-200 transition-colors border border-slate-700"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
        </button>
      </div>

      <div className="mt-4">
        {Array.isArray(data) ? (
          <ul className="space-y-1.5 font-mono text-xs">
            {data.map((item, i) => (
              <li key={i} className="flex items-start gap-2 text-slate-300">
                <span className="text-cyan-500 mt-0.5">•</span>
                <span>{typeof item === 'object' ? JSON.stringify(item) : String(item)}</span>
              </li>
            ))}
          </ul>
        ) : typeof data === 'object' && data !== null ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
            {Object.entries(data).map(([key, val]) => (
              <div key={key} className="p-2 rounded bg-slate-950/60 border border-slate-800">
                <span className="text-slate-400 block text-[10px] uppercase">{key.replace(/_/g, ' ')}</span>
                <span className="text-slate-200 font-semibold truncate block mt-0.5">
                  {typeof val === 'boolean'
                    ? val ? 'TRUE' : 'FALSE'
                    : typeof val === 'object'
                    ? JSON.stringify(val)
                    : String(val)}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs font-mono text-slate-300 whitespace-pre-wrap">{String(data)}</p>
        )}
      </div>
    </div>
  );
};

export default EvidenceCard;
