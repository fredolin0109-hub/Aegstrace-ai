import React, { useEffect, useState } from 'react';
import {
  Settings as SettingsIcon,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Cpu,
  Layers,
  Terminal,
  ShieldCheck,
} from 'lucide-react';
import api from '../services/api';
import { HealthResponse } from '../types';

export const Settings: React.FC = () => {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHealth = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.checkHealth();
      setHealth(data);
    } catch (err: any) {
      setError(err.message || 'Failed to communicate with backend service.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  const PHASES = [
    { num: '01', name: 'FastAPI Backend Core', status: 'COMPLETED (100%)', desc: 'REST API, SQLite/SQLAlchemy schemas, CORS, and audit logs' },
    { num: '02', name: 'DSA Engine', status: 'COMPLETED (100%)', desc: 'Prefix Trie, Graph Cycle Detector, Levenshtein Distance, Max-Heap, MergeSort' },
    { num: '03', name: 'AIML Phishing Engine', status: 'COMPLETED (100%)', desc: '30 lexical/behavioral features, XGBoost model, Explainable AI drivers' },
    { num: '04', name: 'Agentic AI Investigation', status: 'COMPLETED (100%)', desc: '5-phase autonomous loop, multi-tool investigation, immutable audit trail' },
    { num: '05', name: 'Threat Intelligence Aggregator', status: 'COMPLETED (100%)', desc: 'VirusTotal, AbuseIPDB, AlienVault, URLScan & LRU TTL cache' },
    { num: '06', name: 'SOC Frontend Dashboard', status: 'COMPLETED (100%)', desc: 'React, TypeScript, Tailwind CSS, Vite, Real-time Operations Console' },
    { num: '07', name: 'Chrome Browser Extension', status: 'PLANNED (Phase 7)', desc: 'Real-time client-side URL interception and active tab threat warnings' },
    { num: '08', name: 'UiPath RPA Integration', status: 'PLANNED (Phase 8)', desc: 'Production Orchestrator webhook receiver and automated desktop playbooks' },
    { num: '09', name: 'End-to-End Orchestration', status: 'PLANNED (Phase 9)', desc: 'Unified cross-engine integration and stress test validation' },
    { num: '10', name: 'Testing & Production Deployment', status: 'PLANNED (Phase 10)', desc: 'Comprehensive verification, Docker packaging, and documentation' },
  ];

  return (
    <div className="space-y-6 pb-20">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/90 p-6 rounded-xl border border-slate-800">
        <div>
          <h2 className="text-xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
            <SettingsIcon className="w-5 h-5 text-cyan-400" />
            SYSTEM TELEMETRY & ENGINE CONFIGURATION
          </h2>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Real-time backend connectivity diagnostics, environment state, and phase roadmap.
          </p>
        </div>

        <button
          onClick={fetchHealth}
          disabled={loading}
          className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono font-semibold flex items-center gap-2 transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Ping Backend Service</span>
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300 text-xs font-mono flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>Backend unreachable: {error}. Ensure `python -m uvicorn app.main:app` is running on port 8000.</span>
        </div>
      )}

      {/* Backend Diagnostics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 text-xs font-mono">
          <span className="text-slate-400 block text-[10px] uppercase">Service Health</span>
          <div className="mt-1 flex items-center gap-2">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                health?.status === 'healthy' ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'
              }`}
            />
            <span className="text-base font-bold text-white uppercase">
              {health?.status || (loading ? 'CHECKING...' : 'OFFLINE')}
            </span>
          </div>
          <span className="text-slate-500 text-[10px] mt-1 block">
            {health?.service || 'AEGISTRACE Backend API'}
          </span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 text-xs font-mono">
          <span className="text-slate-400 block text-[10px] uppercase">Database Connectivity</span>
          <div className="mt-1 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span className="text-base font-bold text-slate-100 uppercase">
              {health?.database || 'SQLITE'}
            </span>
          </div>
          <span className="text-slate-500 text-[10px] mt-1 block">
            SQLAlchemy ORM + SQLite / Postgres
          </span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 text-xs font-mono">
          <span className="text-slate-400 block text-[10px] uppercase">Operating Mode</span>
          <div className="mt-1 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            <span className="text-base font-bold text-cyan-300">
              {health?.demo_mode ? 'DEMO / SIMULATION' : 'PRODUCTION'}
            </span>
          </div>
          <span className="text-slate-500 text-[10px] mt-1 block">
            Safe RPA containment execution
          </span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 text-xs font-mono">
          <span className="text-slate-400 block text-[10px] uppercase">Environment</span>
          <div className="mt-1 flex items-center gap-2">
            <Terminal className="w-4 h-4 text-amber-400" />
            <span className="text-base font-bold text-slate-100 uppercase">
              {health?.environment || 'DEVELOPMENT'}
            </span>
          </div>
          <span className="text-slate-500 text-[10px] mt-1 block">
            Version {health?.version || '1.0.0'}
          </span>
        </div>
      </div>

      {/* Environment Variables Overview */}
      <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-6">
        <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyan-400" />
          Environment Configuration & API Boundaries
        </h3>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-400 block text-[10px] uppercase">Backend API URL</span>
            <span className="text-slate-200 font-semibold mt-0.5 block truncate">
              {import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'}
            </span>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-400 block text-[10px] uppercase">API Prefix</span>
            <span className="text-slate-200 font-semibold mt-0.5 block">/api</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-400 block text-[10px] uppercase">CORS Allowed Origins</span>
            <span className="text-slate-200 font-semibold mt-0.5 block truncate">
              localhost:5173, localhost:3000, chrome-extension://*
            </span>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-400 block text-[10px] uppercase">UiPath RPA Simulation</span>
            <span className="text-emerald-400 font-semibold mt-0.5 block">TRUE (Safe Demonstration)</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-400 block text-[10px] uppercase">VirusTotal API Key</span>
            <span className="text-slate-300 font-semibold mt-0.5 block">Configured / Local Fallback</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
            <span className="text-slate-400 block text-[10px] uppercase">AbuseIPDB API Key</span>
            <span className="text-slate-300 font-semibold mt-0.5 block">Configured / Local Fallback</span>
          </div>
        </div>
      </div>

      {/* Master 10-Phase Architectural Roadmap */}
      <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-6">
        <h3 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          AEGISTRACE Master 10-Phase Specification Progress
        </h3>

        <div className="space-y-2.5">
          {PHASES.map((phase) => (
            <div
              key={phase.num}
              className={`p-3 rounded-lg border text-xs font-mono flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
                phase.status.includes('COMPLETED')
                  ? 'bg-slate-950/80 border-slate-800'
                  : 'bg-slate-950/40 border-slate-800/60 opacity-60'
              }`}
            >
              <div className="flex items-center gap-3">
                <span className="text-cyan-400 font-bold w-6">{phase.num}</span>
                <div>
                  <span className="font-semibold text-slate-200">{phase.name}</span>
                  <span className="text-slate-400 block text-[11px] mt-0.5">{phase.desc}</span>
                </div>
              </div>

              <div className="sm:text-right">
                <span
                  className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                    phase.status.includes('COMPLETED')
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      : 'bg-slate-800 text-slate-400 border border-slate-700'
                  }`}
                >
                  {phase.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Settings;
