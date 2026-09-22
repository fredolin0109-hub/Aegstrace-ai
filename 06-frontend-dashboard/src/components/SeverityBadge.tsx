import React from 'react';

interface SeverityBadgeProps {
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;
  className?: string;
  size?: 'sm' | 'md' | 'lg';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  className = '',
  size = 'md',
}) => {
  const norm = severity ? severity.toUpperCase() : 'UNKNOWN';

  let colors = 'bg-slate-800 text-slate-300 border-slate-700';
  let dotColor = 'bg-slate-400';

  if (norm === 'LOW') {
    colors = 'bg-emerald-950/60 text-emerald-300 border-emerald-800/60';
    dotColor = 'bg-emerald-400';
  } else if (norm === 'MEDIUM') {
    colors = 'bg-amber-950/60 text-amber-300 border-amber-800/60';
    dotColor = 'bg-amber-400';
  } else if (norm === 'HIGH') {
    colors = 'bg-rose-950/60 text-rose-300 border-rose-800/60';
    dotColor = 'bg-rose-400';
  } else if (norm === 'CRITICAL') {
    colors = 'bg-red-950/80 text-red-200 border-red-700 shadow-sm shadow-red-900/40 animate-pulse';
    dotColor = 'bg-red-500';
  }

  const sizeClasses = {
    sm: 'text-[10px] px-2 py-0.5 tracking-wider font-semibold',
    md: 'text-xs px-2.5 py-1 tracking-wider font-semibold',
    lg: 'text-sm px-3 py-1.5 tracking-wider font-bold',
  }[size];

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border font-mono uppercase ${colors} ${sizeClasses} ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${dotColor}`} />
      {norm}
    </span>
  );
};

export default SeverityBadge;
