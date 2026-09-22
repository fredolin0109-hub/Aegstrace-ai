import React from 'react';

interface StatusBadgeProps {
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE' | 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED' | 'SIMULATED' | string;
  className?: string;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  className = '',
  size = 'md',
}) => {
  const norm = status ? status.toUpperCase() : 'UNKNOWN';

  let colors = 'bg-slate-800 text-slate-300 border-slate-700';

  switch (norm) {
    case 'OPEN':
      colors = 'bg-rose-950/50 text-rose-300 border-rose-800/60';
      break;
    case 'INVESTIGATING':
    case 'RUNNING':
      colors = 'bg-sky-950/60 text-sky-300 border-sky-700/60 animate-pulse';
      break;
    case 'CONTAINED':
      colors = 'bg-violet-950/60 text-violet-300 border-violet-700/60';
      break;
    case 'RESOLVED':
    case 'SUCCESS':
      colors = 'bg-emerald-950/60 text-emerald-300 border-emerald-800/60';
      break;
    case 'FALSE_POSITIVE':
      colors = 'bg-slate-800/70 text-slate-400 border-slate-700';
      break;
    case 'PENDING':
      colors = 'bg-amber-950/50 text-amber-300 border-amber-800/60';
      break;
    case 'FAILED':
      colors = 'bg-red-950/80 text-red-300 border-red-800';
      break;
    case 'SIMULATED':
      colors = 'bg-purple-950/60 text-purple-300 border-purple-700/60';
      break;
    default:
      colors = 'bg-slate-800 text-slate-300 border-slate-700';
  }

  const sizeClasses = {
    sm: 'text-[10px] px-2 py-0.5 font-medium tracking-wide',
    md: 'text-xs px-2.5 py-1 font-semibold tracking-wide',
  }[size];

  return (
    <span
      className={`inline-flex items-center rounded-md border font-mono uppercase ${colors} ${sizeClasses} ${className}`}
    >
      {norm.replace('_', ' ')}
    </span>
  );
};

export default StatusBadge;
