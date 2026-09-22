import React, { useEffect, useState } from 'react';
import { useLocation, Link } from 'react-router-dom';
import { Clock, Shield, RefreshCw } from 'lucide-react';
import api from '../services/api';
import { HealthResponse } from '../types';

export const Topbar: React.FC = () => {
  const location = useLocation();
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [isHealthy, setIsHealthy] = useState<boolean | null>(null);
  const [currentTime, setCurrentTime] = useState<string>('');
  const [checking, setChecking] = useState(false);

  const checkBackendHealth = async () => {
    setChecking(true);
    try {
      const data = await api.checkHealth();
      setHealth(data);
      setIsHealthy(data.status === 'healthy');
    } catch {
      setIsHealthy(false);
    } finally {
      setChecking(false);
    }
  };

  useEffect(() => {
    checkBackendHealth();
    const healthInterval = setInterval(checkBackendHealth, 30000); // 30s poll

    const timer = setInterval(() => {
      const now = new Date();
      setCurrentTime(now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC');
    }, 1000);

    return () => {
      clearInterval(healthInterval);
      clearInterval(timer);
    };
  }, []);

  const getPageTitle = () => {
    const p = location.pathname;
    if (p === '/') return { title: 'SOC Operations Command', breadcrumb: 'DASHBOARD / OVERVIEW' };
    if (p.startsWith('/analyze')) return { title: 'URL Threat Analyzer', breadcrumb: 'OPERATIONS / URL ANALYSIS' };
    if (p.startsWith('/incidents/')) return { title: 'Forensic Incident Investigation', breadcrumb: 'OPERATIONS / INCIDENT DETAILS' };
    if (p.startsWith('/incidents')) return { title: 'Incident Command & Triage', breadcrumb: 'OPERATIONS / INCIDENTS' };
    if (p.startsWith('/threat-intel')) return { title: 'Threat Intelligence Matrix', breadcrumb: 'INTEL / MULTI-PROVIDER' };
    if (p.startsWith('/settings')) return { title: 'System Telemetry & Engine Config', breadcrumb: 'SYSTEM / SETTINGS' };
    return { title: 'Security Console', breadcrumb: 'AEGISTRACE / SOC' };
  };

  const { title, breadcrumb } = getPageTitle();

  return (
    <header className="h-16 bg-slate-950/80 backdrop-blur border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-20">
      {/* Left: Page Title & Breadcrumb */}
      <div>
        <div className="text-[10px] font-mono tracking-widest text-slate-400 uppercase">
          {breadcrumb}
        </div>
        <h2 className="text-base font-semibold font-mono text-slate-100 flex items-center gap-2">
          {title}
        </h2>
      </div>

      {/* Right: SOC Status, Clock & Fast Actions */}
      <div className="flex items-center gap-4">
        {/* Backend Status indicator */}
        <div
          onClick={checkBackendHealth}
          title="Click to re-ping backend API"
          className={`cursor-pointer flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-mono border transition-all ${
            isHealthy === true
              ? 'bg-emerald-950/50 text-emerald-300 border-emerald-800/60 hover:border-emerald-700'
              : isHealthy === false
              ? 'bg-rose-950/60 text-rose-300 border-rose-800 hover:border-rose-700'
              : 'bg-slate-800 text-slate-400 border-slate-700'
          }`}
        >
          <span
            className={`w-2 h-2 rounded-full ${
              isHealthy === true
                ? 'bg-emerald-400 animate-pulse'
                : isHealthy === false
                ? 'bg-rose-500'
                : 'bg-amber-400'
            }`}
          />
          <span>
            {isHealthy === true
              ? `API LIVE ${health?.demo_mode ? '(DEMO)' : ''}`
              : isHealthy === false
              ? 'API OFFLINE'
              : 'CHECKING...'}
          </span>
          <RefreshCw className={`w-3 h-3 ml-1 ${checking ? 'animate-spin' : 'text-slate-400'}`} />
        </div>

        {/* Real-time UTC SOC Clock */}
        <div className="hidden lg:flex items-center gap-1.5 text-xs font-mono text-slate-400 bg-slate-900/80 px-3 py-1 rounded-md border border-slate-800">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span>{currentTime || '00:00:00 UTC'}</span>
        </div>

        {/* Fast Action CTA */}
        <Link
          to="/analyze"
          className="hidden sm:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-mono text-xs font-bold transition-all shadow-[0_0_12px_rgba(6,182,212,0.3)] hover:shadow-[0_0_18px_rgba(6,182,212,0.5)]"
        >
          <Shield className="w-3.5 h-3.5" />
          <span>Scan Target</span>
        </Link>
      </div>
    </header>
  );
};

export default Topbar;
