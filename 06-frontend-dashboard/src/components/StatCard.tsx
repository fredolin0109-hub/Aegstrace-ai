import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: 'cyan' | 'emerald' | 'amber' | 'rose' | 'violet' | 'slate';
  trend?: {
    value: string;
    isPositive: boolean;
  };
  className?: string;
  onClick?: () => void;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = 'cyan',
  trend,
  className = '',
  onClick,
}) => {
  const variantStyles = {
    cyan: {
      border: 'border-cyan-500/20 hover:border-cyan-500/50',
      glow: 'hover:shadow-[0_0_20px_-5px_rgba(6,182,212,0.3)]',
      iconBg: 'bg-cyan-950/60 text-cyan-400 border border-cyan-800/50',
      valueColor: 'text-cyan-100',
    },
    emerald: {
      border: 'border-emerald-500/20 hover:border-emerald-500/50',
      glow: 'hover:shadow-[0_0_20px_-5px_rgba(16,185,129,0.3)]',
      iconBg: 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/50',
      valueColor: 'text-emerald-100',
    },
    amber: {
      border: 'border-amber-500/20 hover:border-amber-500/50',
      glow: 'hover:shadow-[0_0_20px_-5px_rgba(245,158,11,0.3)]',
      iconBg: 'bg-amber-950/60 text-amber-400 border border-amber-800/50',
      valueColor: 'text-amber-100',
    },
    rose: {
      border: 'border-rose-500/20 hover:border-rose-500/50',
      glow: 'hover:shadow-[0_0_20px_-5px_rgba(244,63,94,0.3)]',
      iconBg: 'bg-rose-950/60 text-rose-400 border border-rose-800/50',
      valueColor: 'text-rose-100',
    },
    violet: {
      border: 'border-violet-500/20 hover:border-violet-500/50',
      glow: 'hover:shadow-[0_0_20px_-5px_rgba(139,92,246,0.3)]',
      iconBg: 'bg-violet-950/60 text-violet-400 border border-violet-800/50',
      valueColor: 'text-violet-100',
    },
    slate: {
      border: 'border-slate-700/50 hover:border-slate-600',
      glow: 'hover:shadow-[0_0_20px_-5px_rgba(100,116,139,0.3)]',
      iconBg: 'bg-slate-800/80 text-slate-300 border border-slate-700',
      valueColor: 'text-slate-100',
    },
  }[variant];

  return (
    <div
      onClick={onClick}
      className={`relative overflow-hidden rounded-xl bg-slate-900/80 backdrop-blur-md p-5 border transition-all duration-300 ${
        variantStyles.border
      } ${variantStyles.glow} ${onClick ? 'cursor-pointer' : ''} ${className}`}
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-mono uppercase tracking-wider text-slate-400">{title}</p>
          <div className="mt-2 flex items-baseline gap-2">
            <h3 className={`text-2xl font-bold font-mono tracking-tight ${variantStyles.valueColor}`}>
              {value}
            </h3>
            {trend && (
              <span
                className={`text-xs font-mono font-medium ${
                  trend.isPositive ? 'text-emerald-400' : 'text-rose-400'
                }`}
              >
                {trend.isPositive ? '↑' : '↓'} {trend.value}
              </span>
            )}
          </div>
          {subtitle && <p className="mt-1 text-xs text-slate-400">{subtitle}</p>}
        </div>
        <div className={`rounded-lg p-2.5 ${variantStyles.iconBg}`}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      
      {/* Subtle corner cyber tick */}
      <div className="absolute top-0 right-0 w-2 h-2 border-t border-r border-slate-700/60" />
      <div className="absolute bottom-0 left-0 w-2 h-2 border-b border-l border-slate-700/60" />
    </div>
  );
};

export default StatCard;
