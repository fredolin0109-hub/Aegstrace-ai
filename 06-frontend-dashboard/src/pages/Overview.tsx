import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Radio,
  Zap,
  RefreshCw,
  Search,
  ExternalLink,
  ArrowRight,
  TrendingUp,
} from 'lucide-react';
import api from '../services/api';
import { DashboardStatsResponse } from '../types';
import StatCard from '../components/StatCard';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';

export const Overview: React.FC = () => {
  const [stats, setStats] = useState<DashboardStatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const fetchStats = async () => {
    try {
      setError(null);
      const data = await api.getDashboardStats();
      setStats(data);
    } catch (err: any) {
      console.error('Failed to fetch dashboard stats:', err);
      setError(err.message || 'Unable to connect to backend telemetry.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 15000); // 15s auto-refresh
    return () => clearInterval(interval);
  }, []);

  const handleManualRefresh = () => {
    setRefreshing(true);
    fetchStats();
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner & Quick Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/60 p-5 rounded-xl border border-slate-800">
        <div>
          <h2 className="text-xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
            AEGISTRACE DEFENSE GRID
            <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono">
              LEVEL 1 SOC
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time telemetry from DSA Trie, XGBoost classifier, Autonomous Agent, and UiPath RPA.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleManualRefresh}
            disabled={refreshing}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Sync Feed</span>
          </button>
          <Link
            to="/analyze"
            className="flex items-center gap-2 px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-mono font-bold transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)]"
          >
            <Search className="w-3.5 h-3.5" />
            <span>Scan New URL</span>
          </Link>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/80 text-rose-300 text-xs font-mono flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
            <span>Backend telemetry error: {error}. Check if FastAPI is running on port 8000.</span>
          </div>
          <button onClick={fetchStats} className="underline hover:text-white ml-4">
            Retry
          </button>
        </div>
      )}

      {/* 6 SOC Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard
          title="Total Scanned"
          value={loading ? '...' : (stats?.total_scans ?? 0)}
          subtitle="All analyzed targets"
          icon={Search}
          variant="cyan"
        />
        <StatCard
          title="Safe Targets"
          value={loading ? '...' : (stats?.safe_urls ?? 0)}
          subtitle="Passed all engines"
          icon={ShieldCheck}
          variant="emerald"
        />
        <StatCard
          title="Suspicious"
          value={loading ? '...' : (stats?.suspicious_urls ?? 0)}
          subtitle="Elevated heuristics"
          icon={AlertTriangle}
          variant="amber"
        />
        <StatCard
          title="High Risk"
          value={loading ? '...' : (stats?.high_risk_urls ?? 0)}
          subtitle="Confirmed threat/phish"
          icon={ShieldAlert}
          variant="rose"
        />
        <StatCard
          title="Active Incidents"
          value={loading ? '...' : (stats?.active_incidents ?? 0)}
          subtitle="Pending containment"
          icon={Radio}
          variant="violet"
        />
        <StatCard
          title="RPA Automated"
          value={loading ? '...' : (stats?.automated_responses ?? 0)}
          subtitle="UiPath executed"
          icon={Zap}
          variant="emerald"
        />
      </div>

      {/* Grid: Incident Severity Breakdown & Engine Health */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity & Status Distribution */}
        <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5 lg:col-span-2">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
            <h3 className="text-sm font-semibold font-mono text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-cyan-400" />
              Incident Severity & Triage Distribution
            </h3>
            <span className="text-xs text-slate-400 font-mono">Live Matrix</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 pt-2">
            {/* Severity Bars */}
            <div className="space-y-3">
              <span className="text-xs font-mono uppercase text-slate-400">By Severity</span>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => {
                const count = stats?.severity_breakdown?.[sev] ?? 0;
                const total = Math.max(1, stats?.active_incidents || 1);
                const percent = Math.min(100, Math.round((count / total) * 100));

                let barColor = 'bg-slate-500';
                if (sev === 'CRITICAL') barColor = 'bg-red-500';
                if (sev === 'HIGH') barColor = 'bg-rose-500';
                if (sev === 'MEDIUM') barColor = 'bg-amber-500';
                if (sev === 'LOW') barColor = 'bg-emerald-500';

                return (
                  <div key={sev} className="space-y-1 text-xs font-mono">
                    <div className="flex justify-between text-slate-300">
                      <span>{sev}</span>
                      <span className="text-slate-400">{count} incident{count === 1 ? '' : 's'}</span>
                    </div>
                    <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${barColor} transition-all duration-500 rounded-full`}
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Status Breakdown */}
            <div className="space-y-3">
              <span className="text-xs font-mono uppercase text-slate-400">By SOC Status</span>
              {['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'].map((st) => {
                const count = stats?.status_breakdown?.[st] ?? 0;
                const total = Math.max(1, Object.values(stats?.status_breakdown || {}).reduce((a, b) => a + b, 0) || 1);
                const percent = Math.min(100, Math.round((count / total) * 100));

                return (
                  <div key={st} className="space-y-1 text-xs font-mono">
                    <div className="flex justify-between text-slate-300">
                      <span>{st}</span>
                      <span className="text-slate-400">{count}</span>
                    </div>
                    <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-cyan-500 transition-all duration-500 rounded-full"
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Quick Triage CTA */}
        <div className="rounded-xl bg-gradient-to-br from-slate-900 via-slate-900 to-cyan-950/40 border border-cyan-500/20 p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
              <h4 className="text-sm font-semibold font-mono text-cyan-200 uppercase tracking-wider">
                DSA Priority Triage
              </h4>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed font-mono">
              The 02-dsa-engine Indexed Max-Heap prioritizes high-risk incidents instantly. Zero manual searching required.
            </p>

            <div className="mt-4 p-3 rounded-lg bg-slate-950/70 border border-slate-800 text-xs font-mono space-y-1.5">
              <div className="flex justify-between text-slate-400">
                <span>Active in Queue:</span>
                <span className="text-rose-400 font-bold">{stats?.active_incidents ?? 0}</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Auto-Containment:</span>
                <span className="text-emerald-400 font-bold">Enabled</span>
              </div>
            </div>
          </div>

          <Link
            to="/incidents"
            className="mt-6 flex items-center justify-center gap-2 w-full py-2.5 rounded-lg bg-cyan-600/90 hover:bg-cyan-500 text-slate-950 font-mono text-xs font-bold transition-all"
          >
            <span>Open Incident Command</span>
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </div>

      {/* Two Columns: Recent Scans & Recent Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Scans Feed */}
        <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
            <h3 className="text-sm font-semibold font-mono text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Search className="w-4 h-4 text-cyan-400" />
              Recent URL Threat Scans
            </h3>
            <Link
              to="/analyze"
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              <span>Scan URL</span>
              <ExternalLink className="w-3 h-3" />
            </Link>
          </div>

          {stats?.recent_scans && stats.recent_scans.length > 0 ? (
            <div className="space-y-2.5">
              {stats.recent_scans.map((scan) => (
                <div
                  key={scan.id}
                  className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-center justify-between gap-3 text-xs font-mono hover:bg-slate-950 transition-colors"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-slate-200 truncate" title={scan.url}>
                        {scan.domain || scan.url}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 truncate mt-0.5" title={scan.url}>
                      {scan.url}
                    </p>
                  </div>

                  <div className="flex items-center gap-3 flex-shrink-0">
                    <div className="text-right">
                      <span className="text-[10px] text-slate-400 block">Risk Score</span>
                      <span
                        className={`text-xs font-bold ${
                          scan.risk_score >= 0.7
                            ? 'text-rose-400'
                            : scan.risk_score >= 0.35
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {(scan.risk_score * 100).toFixed(0)}%
                      </span>
                    </div>
                    <SeverityBadge
                      severity={
                        scan.classification === 'HIGH_RISK'
                          ? 'HIGH'
                          : scan.classification === 'SUSPICIOUS'
                          ? 'MEDIUM'
                          : 'LOW'
                      }
                      size="sm"
                    />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-slate-400 text-xs font-mono">
              No recent scans recorded yet. Enter a target in the URL Threat Analyzer.
            </div>
          )}
        </div>

        {/* Recent Incidents Feed */}
        <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
            <h3 className="text-sm font-semibold font-mono text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              Active Incident Queue
            </h3>
            <Link
              to="/incidents"
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              <span>View All</span>
              <ExternalLink className="w-3 h-3" />
            </Link>
          </div>

          {stats?.recent_incidents && stats.recent_incidents.length > 0 ? (
            <div className="space-y-2.5">
              {stats.recent_incidents.map((inc) => (
                <Link
                  key={inc.id}
                  to={`/incidents/${inc.id}`}
                  className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-center justify-between gap-3 text-xs font-mono hover:border-slate-700 transition-colors block"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-cyan-400 font-bold">{inc.incident_number}</span>
                      <span className="text-slate-300 truncate font-medium">{inc.title}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 truncate mt-0.5">{inc.url}</p>
                  </div>

                  <div className="flex items-center gap-2 flex-shrink-0">
                    <SeverityBadge severity={inc.severity} size="sm" />
                    <StatusBadge status={inc.status} size="sm" />
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-slate-400 text-xs font-mono">
              No active incidents in queue. All systems operating securely.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Overview;
