import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  ScanLine,
  ShieldAlert,
  Globe2,
  Settings,
  ShieldCheck,
  Terminal,
} from 'lucide-react';

const NAV_ITEMS = [
  { path: '/', label: 'SOC Overview', icon: LayoutDashboard },
  { path: '/analyze', label: 'URL Threat Analyzer', icon: ScanLine },
  { path: '/incidents', label: 'Incident Command', icon: ShieldAlert },
  { path: '/threat-intel', label: 'Threat Intelligence', icon: Globe2 },
  { path: '/settings', label: 'System Telemetry', icon: Settings },
];

export const Sidebar: React.FC = () => {
  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-800/80 flex flex-col h-screen sticky top-0 z-30 select-none">
      {/* Brand Header */}
      <div className="h-16 flex items-center px-6 border-b border-slate-800/80 bg-slate-950/50 backdrop-blur">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-950/80 border border-cyan-500/50 flex items-center justify-center shadow-[0_0_12px_rgba(6,182,212,0.3)]">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h1 className="font-mono font-bold tracking-wider text-base text-white flex items-center gap-1.5">
              AEGISTRACE
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            </h1>
            <p className="text-[10px] font-mono tracking-widest text-slate-400 uppercase">
              AUTONOMOUS SOC
            </p>
          </div>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-6 space-y-1.5 overflow-y-auto">
        <div className="px-3 pb-2 text-[10px] font-mono uppercase tracking-wider text-slate-400">
          Core Operations
        </div>

        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-mono font-medium transition-all duration-200 ${
                  isActive
                    ? 'bg-cyan-950/70 text-cyan-300 border border-cyan-700/60 shadow-[0_0_15px_-3px_rgba(6,182,212,0.25)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/80'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <Icon
                    className={`w-4 h-4 transition-colors ${
                      isActive ? 'text-cyan-400' : 'text-slate-500'
                    }`}
                  />
                  <span>{item.label}</span>
                  {isActive && (
                    <span className="ml-auto w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-[0_0_6px_rgba(6,182,212,0.8)]" />
                  )}
                </>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Subsystem Telemetry Badge */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-900/40">
        <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 text-[11px] font-mono">
          <div className="flex items-center justify-between text-slate-400 mb-1.5">
            <span className="flex items-center gap-1.5 text-slate-300 font-semibold">
              <Terminal className="w-3.5 h-3.5 text-emerald-400" />
              ENGINE STATUS
            </span>
            <span className="text-[10px] text-emerald-400 font-bold">ONLINE</span>
          </div>
          <div className="space-y-1 text-[10px] text-slate-400">
            <div className="flex justify-between">
              <span>DSA Trie & Graph:</span>
              <span className="text-cyan-400">READY</span>
            </div>
            <div className="flex justify-between">
              <span>AIML Classifier:</span>
              <span className="text-cyan-400">READY</span>
            </div>
            <div className="flex justify-between">
              <span>Agentic AI:</span>
              <span className="text-violet-400">AUTONOMOUS</span>
            </div>
            <div className="flex justify-between">
              <span>UiPath RPA:</span>
              <span className="text-emerald-400">READY</span>
            </div>
          </div>
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
