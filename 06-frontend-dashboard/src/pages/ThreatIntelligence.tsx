import React, { useEffect, useState } from 'react';
import {
  Globe2,
  Search,
  Database,
  Trash2,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Server,
  Zap,
} from 'lucide-react';
import api from '../services/api';
import { ThreatIntelLookupResponse, ThreatIntelStatsResponse } from '../types';
import ThreatScoreGauge from '../components/ThreatScoreGauge';
import StatCard from '../components/StatCard';

const PROVIDERS = [
  { id: 'virustotal', name: 'VirusTotal v3', desc: '70+ antivirus engines & URL scanners' },
  { id: 'abuseipdb', name: 'AbuseIPDB v2', desc: 'IP reputation & crowdsourced abuse reports' },
  { id: 'alienvault', name: 'AlienVault OTX', desc: 'Open Threat Exchange pulses & IOC feeds' },
  { id: 'urlscan', name: 'URLScan.io', desc: 'Automated headless browser DOM & network scanner' },
  { id: 'local', name: 'Local Engine (02-dsa)', desc: 'Zero-credential Trie, Graph & Levenshtein fallback' },
];

export const ThreatIntelligence: React.FC = () => {
  const [target, setTarget] = useState('');
  const [targetType, setTargetType] = useState<string>('auto');
  const [forceRefresh, setForceRefresh] = useState(false);

  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<ThreatIntelLookupResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Cache stats & source availability
  const [stats, setStats] = useState<ThreatIntelStatsResponse | null>(null);
  const [flushing, setFlushing] = useState(false);
  const [flushMessage, setFlushMessage] = useState<string | null>(null);

  const fetchStats = async () => {
    try {
      const data = await api.getThreatIntelStats();
      setStats(data);
    } catch (e: any) {
      console.warn('Failed to fetch threat intel stats:', e);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  const handleLookup = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const query = target.trim();
    if (!query) return;

    setLoading(true);
    setError(null);
    setReport(null);

    try {
      const actualType = targetType === 'auto' ? undefined : targetType;
      const data = await api.lookupThreatIntel(query, actualType, forceRefresh);
      setReport(data);
      fetchStats(); // Update cache telemetry
    } catch (err: any) {
      setError(err.message || 'Threat intelligence query failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleClearCache = async () => {
    setFlushing(true);
    setFlushMessage(null);
    try {
      const res = await api.clearThreatIntelCache();
      setFlushMessage(res.message || 'Cache flushed.');
      fetchStats();
      setTimeout(() => setFlushMessage(null), 3000);
    } catch (err: any) {
      alert(`Flush failed: ${err.message}`);
    } finally {
      setFlushing(false);
    }
  };

  return (
    <div className="space-y-6 pb-16">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/90 p-6 rounded-xl border border-slate-800">
        <div>
          <h2 className="text-xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
            <Globe2 className="w-5 h-5 text-cyan-400" />
            MULTI-PROVIDER THREAT INTELLIGENCE MATRIX
          </h2>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Aggregates VirusTotal, AbuseIPDB, AlienVault OTX, and URLScan with high-speed LRU TTL caching.
          </p>
        </div>

        <button
          onClick={handleClearCache}
          disabled={flushing}
          className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-rose-950 text-slate-300 hover:text-rose-300 border border-slate-700 hover:border-rose-700 font-mono text-xs font-semibold flex items-center gap-2 transition-colors disabled:opacity-50"
        >
          <Trash2 className="w-3.5 h-3.5" />
          <span>{flushing ? 'Flushing...' : 'Flush In-Memory Cache'}</span>
        </button>
      </div>

      {flushMessage && (
        <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-800 text-emerald-300 text-xs font-mono flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{flushMessage}</span>
        </div>
      )}

      {/* Cache Diagnostics Stats Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Cached Entries"
          value={stats?.cache_stats?.entries ?? 0}
          subtitle="In-memory LRU storage"
          icon={Database}
          variant="cyan"
        />
        <StatCard
          title="Cache Hits"
          value={stats?.cache_stats?.hits ?? 0}
          subtitle="Served with 0ms latency"
          icon={Zap}
          variant="emerald"
        />
        <StatCard
          title="Cache Misses"
          value={stats?.cache_stats?.misses ?? 0}
          subtitle="Upstream queries made"
          icon={Server}
          variant="amber"
        />
        <StatCard
          title="Hit Ratio"
          value={`${((stats?.cache_stats?.hit_ratio ?? 0) * 100).toFixed(1)}%`}
          subtitle="Cache efficiency metric"
          icon={CheckCircle2}
          variant="violet"
        />
      </div>

      {/* Search Bar & Options */}
      <div className="rounded-xl bg-slate-900/80 border border-slate-800 p-6">
        <form onSubmit={handleLookup}>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="Enter domain, IPv4/IPv6, or URL (e.g. 185.220.101.5, example-phish.ru, or google.com)..."
                className="w-full h-12 bg-slate-950 border border-slate-700 focus:border-cyan-500 rounded-lg px-4 font-mono text-sm text-slate-100 placeholder-slate-500 focus:outline-none"
              />
            </div>

            <div className="flex items-center gap-2 flex-shrink-0">
              <select
                value={targetType}
                onChange={(e) => setTargetType(e.target.value)}
                className="h-12 bg-slate-950 border border-slate-700 rounded-lg px-3 text-xs font-mono text-slate-200 focus:outline-none"
              >
                <option value="auto">Auto-Detect Type</option>
                <option value="domain">Domain Only</option>
                <option value="ip">IP Address Only</option>
                <option value="url">URL Only</option>
              </select>

              <button
                type="submit"
                disabled={loading || !target.trim()}
                className="h-12 px-6 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-mono text-sm font-bold flex items-center gap-2 transition-all shadow-[0_0_15px_rgba(6,182,212,0.4)] disabled:opacity-50"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Querying...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4" />
                    <span>Run Intel Query</span>
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="mt-3 flex items-center gap-4 text-xs font-mono text-slate-400">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={forceRefresh}
                onChange={(e) => setForceRefresh(e.target.checked)}
                className="rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-0"
              />
              <span>Force Upstream Refresh (Bypass Cache)</span>
            </label>

            <span className="text-slate-600">•</span>

            <span className="text-[11px] text-slate-400">
              Quick tests:{' '}
              <button
                type="button"
                onClick={() => {
                  setTarget('8.8.8.8');
                  setTargetType('ip');
                }}
                className="text-cyan-400 hover:underline mr-2"
              >
                8.8.8.8 (Google DNS)
              </button>
              <button
                type="button"
                onClick={() => {
                  setTarget('malicious-credential-harvest.ru');
                  setTargetType('domain');
                }}
                className="text-cyan-400 hover:underline mr-2"
              >
                phish-domain.ru
              </button>
              <button
                type="button"
                onClick={() => {
                  setTarget('185.220.101.5');
                  setTargetType('ip');
                }}
                className="text-cyan-400 hover:underline"
              >
                Tor Exit Node IP
              </button>
            </span>
          </div>
        </form>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300 text-xs font-mono flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Lookup Report Display */}
      {report && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Gauge */}
            <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-6 flex flex-col items-center justify-center text-center">
              <ThreatScoreGauge
                score={report.composite_score}
                classification={report.verdict}
                confidence={report.confidence}
                size={190}
              />
              <div className="mt-4 pt-3 border-t border-slate-800/80 w-full flex justify-between text-xs font-mono text-slate-400">
                <span>Source Response:</span>
                <span className={report.cached ? 'text-cyan-400 font-bold' : 'text-emerald-400 font-bold'}>
                  {report.cached ? 'SERVED FROM CACHE' : 'LIVE UPSTREAM'}
                </span>
              </div>
            </div>

            {/* Target Metadata & Sources */}
            <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-6 lg:col-span-2 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
                    TARGET: {report.target}
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    Queried: {new Date(report.timestamp).toLocaleTimeString()}
                  </span>
                </div>

                <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-slate-400 text-[10px] block uppercase">Target Type</span>
                    <span className="text-slate-200 font-semibold uppercase">{report.target_type}</span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                    <span className="text-slate-400 text-[10px] block uppercase">Confidence Level</span>
                    <span className="text-slate-200 font-semibold">{(report.confidence * 100).toFixed(0)}%</span>
                  </div>
                </div>

                <div className="mt-4">
                  <span className="text-xs font-mono uppercase text-slate-400 block mb-2">
                    Consulted Threat Providers ({report.sources_consulted.length})
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {report.sources_consulted.map((source) => (
                      <span
                        key={source}
                        className="px-2.5 py-1 rounded bg-slate-950 border border-slate-700 text-xs font-mono text-slate-300 flex items-center gap-1.5"
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                        {source}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {report.domain_info && (
                <div className="mt-4 pt-3 border-t border-slate-800 text-xs font-mono text-slate-400">
                  <span className="block text-[10px] uppercase text-slate-400 mb-1">DNS / WHOIS Context:</span>
                  <pre className="text-slate-300 text-[11px] bg-slate-950 p-2 rounded border border-slate-800/80 overflow-x-auto">
                    {JSON.stringify(report.domain_info, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>

          {/* Provider Details Breakdown */}
          {report.provider_details && Object.keys(report.provider_details).length > 0 && (
            <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-6">
              <h4 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-400" />
                Raw Provider Threat Reports
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {Object.entries(report.provider_details).map(([providerName, pDetails]: [string, any]) => (
                  <div
                    key={providerName}
                    className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 text-xs font-mono space-y-2"
                  >
                    <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                      <span className="font-bold text-slate-200 uppercase">{providerName}</span>
                      <span className="text-slate-400 text-[10px]">
                        {pDetails?.verdict || (pDetails?.is_malicious ? 'MALICIOUS' : 'CLEAN')}
                      </span>
                    </div>

                    <pre className="p-2 rounded bg-slate-900 text-slate-300 text-[11px] overflow-x-auto max-h-48">
                      {JSON.stringify(pDetails, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Provider Matrix Reference */}
      <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-6">
        <h4 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
          <Database className="w-4 h-4 text-cyan-400" />
          Configured Upstream Intelligence Providers
        </h4>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {PROVIDERS.map((prov) => {
            const isAvailable = stats?.available_sources?.includes(prov.id) ?? true;

            return (
              <div
                key={prov.id}
                className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono font-bold text-slate-200">{prov.name}</span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase font-semibold ${
                        isAvailable
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          : 'bg-amber-950 text-amber-300 border border-amber-800'
                      }`}
                    >
                      {isAvailable ? 'CONFIGURED' : 'FALLBACK'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 font-mono leading-relaxed">{prov.desc}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export default ThreatIntelligence;
