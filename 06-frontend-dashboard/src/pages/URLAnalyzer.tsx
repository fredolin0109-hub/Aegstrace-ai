import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  AlertTriangle,
  Cpu,
  Network,
  Shield,
  Bot,
  Zap,
  ArrowRight,
  RefreshCw,
  Sliders,
  CheckCircle2,
} from 'lucide-react';
import api from '../services/api';
import { ScanResponse, InvestigateResponse } from '../types';
import ThreatScoreGauge from '../components/ThreatScoreGauge';
import ThreatIndicatorList from '../components/ThreatIndicatorList';
import AuditTimeline from '../components/AuditTimeline';
import EvidenceCard from '../components/EvidenceCard';

const SAMPLE_TARGETS = [
  {
    label: 'PayPal Phish (High Risk)',
    url: 'http://login.paypal-security-update.com/signin/verify-account',
    type: 'HIGH_RISK',
  },
  {
    label: 'Suspicious Subdomain',
    url: 'https://security-notice.verify-online-portal.net/account/auth',
    type: 'SUSPICIOUS',
  },
  {
    label: 'Legitimate Portal (Safe)',
    url: 'https://github.com',
    type: 'SAFE',
  },
];

export const URLAnalyzer: React.FC = () => {
  const navigate = useNavigate();
  const [url, setUrl] = useState('');
  const [clientIp, setClientIp] = useState('');
  const [userAgent, setUserAgent] = useState('');
  const [redirectChainStr, setRedirectChainStr] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // Autonomous Agent Investigation State
  const [investigating, setInvestigating] = useState(false);
  const [investigationResult, setInvestigationResult] = useState<InvestigateResponse | null>(null);
  const [investigationError, setInvestigationError] = useState<string | null>(null);

  // UiPath trigger state
  const [triggeringRpa, setTriggeringRpa] = useState(false);
  const [rpaSuccess, setRpaSuccess] = useState<string | null>(null);

  const handleScan = async (targetUrl?: string) => {
    const finalUrl = (targetUrl || url).trim();
    if (!finalUrl) return;

    setUrl(finalUrl);
    setScanning(true);
    setScanError(null);
    setScanResult(null);
    setInvestigationResult(null);
    setInvestigationError(null);
    setRpaSuccess(null);

    try {
      const redirectChain = redirectChainStr
        ? redirectChainStr.split('\n').map((s) => s.trim()).filter(Boolean)
        : undefined;

      const result = await api.analyzeUrl({
        url: finalUrl,
        client_ip: clientIp || undefined,
        user_agent: userAgent || undefined,
        redirect_chain: redirectChain,
      });
      setScanResult(result);
    } catch (err: any) {
      setScanError(err.message || 'Analysis failed. Please verify target URL format.');
    } finally {
      setScanning(false);
    }
  };

  const handleRunAgentInvestigation = async () => {
    if (!scanResult) return;
    setInvestigating(true);
    setInvestigationError(null);

    try {
      const inv = await api.investigateUrl({
        url: scanResult.url,
        url_scan_id: scanResult.id,
        depth: 'standard',
        force_escalate: scanResult.risk_score >= 0.7,
      });
      setInvestigationResult(inv);
    } catch (err: any) {
      setInvestigationError(err.message || 'Agent investigation failed.');
    } finally {
      setInvestigating(false);
    }
  };

  const handleTriggerRpaContainment = async () => {
    if (!investigationResult?.incident_id) return;
    setTriggeringRpa(true);
    try {
      const rpaRes = await api.triggerUiPathAction({
        incident_id: investigationResult.incident_id,
        action_type: 'CONTAIN_HOST',
        parameters: { target_url: scanResult?.url },
      });
      setRpaSuccess(`UiPath RPA Dispatched! Job Execution ID: ${rpaRes.execution_id}`);
    } catch (err: any) {
      setInvestigationError(`Failed to trigger UiPath RPA: ${err.message}`);
    } finally {
      setTriggeringRpa(false);
    }
  };

  return (
    <div className="space-y-6 pb-16">
      {/* Search Header */}
      <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-6 shadow-xl">
        <div className="max-w-3xl">
          <h2 className="text-xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
            <Search className="w-5 h-5 text-cyan-400" />
            TARGET URL FORENSIC ANALYZER
          </h2>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Execute deterministic DSA keyword filtering, XGBoost behavioral classification, and multi-source threat intelligence.
          </p>
        </div>

        {/* Input Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleScan();
          }}
          className="mt-6"
        >
          <div className="flex flex-col sm:flex-row gap-2">
            <div className="relative flex-1">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter URL to inspect (e.g. https://login.secure-bank.phish.com/auth)..."
                className="w-full h-12 bg-slate-950 border border-slate-700 focus:border-cyan-500 rounded-lg px-4 font-mono text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
            </div>
            <button
              type="submit"
              disabled={scanning || !url.trim()}
              className="h-12 px-6 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-mono text-sm font-bold flex items-center justify-center gap-2 transition-all shadow-[0_0_15px_rgba(6,182,212,0.4)] disabled:opacity-50 flex-shrink-0"
            >
              {scanning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Inspecting...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>Inspect Target</span>
                </>
              )}
            </button>
          </div>

          {/* Quick preset chips */}
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <span className="text-[11px] font-mono text-slate-400">Quick Samples:</span>
            {SAMPLE_TARGETS.map((sample, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setUrl(sample.url);
                  handleScan(sample.url);
                }}
                className={`text-[11px] font-mono px-2.5 py-1 rounded border transition-colors ${
                  sample.type === 'HIGH_RISK'
                    ? 'bg-rose-950/40 text-rose-300 border-rose-800/60 hover:bg-rose-900/60'
                    : sample.type === 'SUSPICIOUS'
                    ? 'bg-amber-950/40 text-amber-300 border-amber-800/60 hover:bg-amber-900/60'
                    : 'bg-emerald-950/40 text-emerald-300 border-emerald-800/60 hover:bg-emerald-900/60'
                }`}
              >
                {sample.label}
              </button>
            ))}

            <button
              type="button"
              onClick={() => setShowAdvanced(!showAdvanced)}
              className="ml-auto text-[11px] font-mono text-slate-400 hover:text-slate-200 flex items-center gap-1"
            >
              <Sliders className="w-3 h-3" />
              <span>{showAdvanced ? 'Hide Advanced' : 'Advanced Parameters'}</span>
            </button>
          </div>

          {/* Advanced Parameters Drawer */}
          {showAdvanced && (
            <div className="mt-4 p-4 rounded-lg bg-slate-950/70 border border-slate-800 grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Simulated Client IP</label>
                <input
                  type="text"
                  value={clientIp}
                  onChange={(e) => setClientIp(e.target.value)}
                  placeholder="e.g. 192.168.1.100"
                  className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Client User Agent</label>
                <input
                  type="text"
                  value={userAgent}
                  onChange={(e) => setUserAgent(e.target.value)}
                  placeholder="e.g. Mozilla/5.0 Chrome/120..."
                  className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200"
                />
              </div>
              <div className="sm:col-span-2">
                <label className="block text-slate-400 mb-1">Observed Redirect Chain (one URL per line)</label>
                <textarea
                  rows={2}
                  value={redirectChainStr}
                  onChange={(e) => setRedirectChainStr(e.target.value)}
                  placeholder="https://hop1.bit.ly/xyz&#10;https://hop2.phish.cc/entry"
                  className="w-full bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-slate-200"
                />
              </div>
            </div>
          )}
        </form>
      </div>

      {/* Error Message */}
      {scanError && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300 text-xs font-mono flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{scanError}</span>
        </div>
      )}

      {/* Loading Radar */}
      {scanning && (
        <div className="p-12 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col items-center justify-center text-center">
          <div className="w-16 h-16 rounded-full border-4 border-cyan-500/20 border-t-cyan-400 animate-spin mb-4" />
          <h3 className="text-base font-mono font-bold text-cyan-300">
            PROCESSING MULTI-STAGE ANALYSIS
          </h3>
          <p className="text-xs font-mono text-slate-400 mt-1 max-w-md">
            Querying DSA Trie lookup, graph redirect topology, AIML risk scoring, and threat reputation feeds...
          </p>
        </div>
      )}

      {/* Analysis Results Display */}
      {scanResult && !scanning && (
        <div className="space-y-6">
          {/* Main Verdict Banner */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Risk Gauge Card */}
            <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-6 flex flex-col items-center justify-center text-center">
              <ThreatScoreGauge
                score={scanResult.risk_score}
                classification={scanResult.classification}
                confidence={scanResult.confidence}
                size={200}
              />
              <div className="mt-4 pt-4 border-t border-slate-800/80 w-full flex justify-between text-xs font-mono text-slate-400">
                <span>Recommendation:</span>
                <span
                  className={`font-bold uppercase ${
                    scanResult.recommendation === 'BLOCK'
                      ? 'text-rose-400'
                      : scanResult.recommendation === 'WARN' || scanResult.recommendation === 'INVESTIGATE'
                      ? 'text-amber-400'
                      : 'text-emerald-400'
                  }`}
                >
                  {scanResult.recommendation}
                </span>
              </div>
            </div>

            {/* Target Overview Metadata */}
            <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-6 lg:col-span-2 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
                    SCAN RESULT ID #{scanResult.id}
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    {new Date(scanResult.created_at).toLocaleString()}
                  </span>
                </div>

                <div className="mt-4 space-y-2 font-mono text-xs">
                  <div>
                    <span className="text-slate-400 block text-[10px] uppercase">Target URL</span>
                    <span className="text-slate-100 font-semibold break-all text-sm">{scanResult.url}</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
                    <div>
                      <span className="text-slate-400 block text-[10px] uppercase">Extracted Domain</span>
                      <span className="text-slate-200">{scanResult.domain || 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-slate-400 block text-[10px] uppercase">IP Address</span>
                      <span className="text-slate-200">{scanResult.ip_address || 'Unresolved / Inactive'}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Action Buttons: Agent Investigation */}
              <div className="mt-6 pt-4 border-t border-slate-800 flex flex-wrap items-center justify-between gap-3">
                <div className="text-xs font-mono text-slate-400">
                  <span>Automated SOC Triaging:</span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleRunAgentInvestigation}
                    disabled={investigating}
                    className="px-4 py-2 rounded-lg bg-violet-600 hover:bg-violet-500 text-white font-mono text-xs font-bold flex items-center gap-2 transition-all shadow-[0_0_12px_rgba(139,92,246,0.4)] disabled:opacity-50"
                  >
                    <Bot className="w-4 h-4" />
                    <span>{investigating ? 'Investigating...' : 'Launch Autonomous Agent'}</span>
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* 3 Engine Forensic Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* DSA Engine Findings */}
            <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-5">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-800 text-emerald-400 font-mono text-xs font-bold uppercase">
                <Network className="w-4 h-4" />
                <span>02-DSA Engine</span>
              </div>
              <div className="mt-3 space-y-2 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-400">DSA Verdict:</span>
                  <span className="text-slate-200 font-bold">{scanResult.dsa_verdict || 'SAFE'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">DSA Risk Score:</span>
                  <span className="text-emerald-400 font-bold">
                    {scanResult.dsa_risk_score !== undefined && scanResult.dsa_risk_score !== null
                      ? `${(scanResult.dsa_risk_score * 100).toFixed(0)}%`
                      : '0%'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Graph Cycles:</span>
                  <span className={scanResult.graph_summary?.has_cycles ? 'text-rose-400' : 'text-slate-300'}>
                    {scanResult.graph_summary?.has_cycles ? 'DETECTED' : 'None'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Redirect Hops:</span>
                  <span className="text-slate-300">
                    {scanResult.graph_summary?.max_redirect_depth ?? 0}
                  </span>
                </div>
              </div>
            </div>

            {/* AIML Engine Findings */}
            <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-5">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-800 text-cyan-400 font-mono text-xs font-bold uppercase">
                <Cpu className="w-4 h-4" />
                <span>03-AIML Engine</span>
              </div>
              <div className="mt-3 space-y-2 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-400">ML Classification:</span>
                  <span className="text-slate-200 font-bold">{scanResult.ml_classification || scanResult.classification}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Phishing Probability:</span>
                  <span className="text-cyan-400 font-bold">
                    {scanResult.ml_risk_score !== undefined && scanResult.ml_risk_score !== null
                      ? `${(scanResult.ml_risk_score * 100).toFixed(0)}%`
                      : `${(scanResult.risk_score * 100).toFixed(0)}%`}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Confidence:</span>
                  <span className="text-slate-300">
                    {scanResult.ml_confidence !== undefined && scanResult.ml_confidence !== null
                      ? `${(scanResult.ml_confidence * 100).toFixed(0)}%`
                      : `${(scanResult.confidence * 100).toFixed(0)}%`}
                  </span>
                </div>
                {scanResult.ml_explanations && scanResult.ml_explanations.length > 0 && (
                  <div className="pt-1">
                    <span className="text-slate-400 block text-[10px]">Key Drivers:</span>
                    <p className="text-slate-300 text-[11px] truncate">
                      {scanResult.ml_explanations.join(', ')}
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Threat Intel Findings */}
            <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-5">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-800 text-amber-400 font-mono text-xs font-bold uppercase">
                <Shield className="w-4 h-4" />
                <span>05-Threat Intel</span>
              </div>
              <div className="mt-3 space-y-2 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-slate-400">Intel Score:</span>
                  <span className="text-amber-400 font-bold">
                    {scanResult.threat_intel_score !== undefined && scanResult.threat_intel_score !== null
                      ? `${(scanResult.threat_intel_score * 100).toFixed(0)}%`
                      : 'N/A'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Verdict:</span>
                  <span className="text-slate-200 font-bold">{scanResult.threat_intel_verdict || 'CLEAN'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Providers Consulted:</span>
                  <span className="text-slate-300 truncate max-w-[120px]">
                    {scanResult.threat_intel_sources?.length
                      ? scanResult.threat_intel_sources.join(', ')
                      : 'Local Fallback'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* IOC Indicators List */}
          <ThreatIndicatorList indicators={scanResult.indicators} />

          {/* Autonomous Agent Investigation Trace Panel (if triggered) */}
          {investigating && (
            <div className="p-8 rounded-xl bg-slate-900/80 border border-violet-800/60 flex flex-col items-center justify-center text-center">
              <Bot className="w-10 h-10 text-violet-400 animate-bounce mb-3" />
              <h4 className="text-sm font-mono font-bold text-violet-300">
                AUTONOMOUS AGENT ACTIVE INVESTIGATION
              </h4>
              <p className="text-xs font-mono text-slate-400 mt-1 max-w-lg">
                The AI Agent is autonomously executing multi-step evidence gathering, checking domain registration anomalies, evaluating incident escalation thresholds, and preparing containment.
              </p>
            </div>
          )}

          {investigationError && (
            <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300 text-xs font-mono">
              Agent error: {investigationError}
            </div>
          )}

          {investigationResult && (
            <div className="rounded-xl bg-slate-900/90 border border-violet-800/60 p-6 space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-lg bg-violet-950 border border-violet-700 text-violet-400">
                    <Bot className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-sm font-mono font-bold text-violet-200 uppercase tracking-wider">
                      Autonomous Investigation Completed
                    </h3>
                    <p className="text-xs font-mono text-slate-400 mt-0.5">
                      Decision: <span className="text-white font-bold">{investigationResult.decision}</span>
                    </p>
                  </div>
                </div>

                {investigationResult.incident_created && investigationResult.incident_id && (
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => navigate(`/incidents/${investigationResult.incident_id}`)}
                      className="px-3.5 py-1.5 rounded-lg bg-rose-950 text-rose-300 border border-rose-800 hover:bg-rose-900 text-xs font-mono font-bold flex items-center gap-1.5"
                    >
                      <span>Incident {investigationResult.incident_number}</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}
              </div>

              {/* Timeline showing stages */}
              <AuditTimeline
                currentStage={
                  investigationResult.incident_created
                    ? 'DECIDED'
                    : 'INVESTIGATED'
                }
                agentTraces={investigationResult.action_trace}
              />

              {/* Evidence cards */}
              {investigationResult.evidence_collected && investigationResult.evidence_collected.length > 0 && (
                <EvidenceCard
                  title="Agent Evidence Artifacts"
                  category="AIML"
                  data={investigationResult.evidence_collected}
                />
              )}

              {/* 1-Click RPA Containment Trigger */}
              {investigationResult.incident_id && (
                <div className="p-4 rounded-xl bg-slate-950 border border-emerald-800/60 flex flex-col sm:flex-row items-center justify-between gap-4">
                  <div>
                    <h4 className="text-xs font-mono font-bold text-emerald-300 uppercase tracking-wider flex items-center gap-2">
                      <Zap className="w-4 h-4 text-emerald-400" />
                      UiPath RPA Incident Containment
                    </h4>
                    <p className="text-[11px] font-mono text-slate-400 mt-0.5">
                      Dispatch automated endpoint host containment and block domain in firewall proxy.
                    </p>
                  </div>

                  <button
                    onClick={handleTriggerRpaContainment}
                    disabled={triggeringRpa}
                    className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-mono text-xs font-bold flex items-center gap-2 transition-all shadow-[0_0_12px_rgba(16,185,129,0.4)] disabled:opacity-50 flex-shrink-0"
                  >
                    <Zap className="w-3.5 h-3.5" />
                    <span>{triggeringRpa ? 'Dispatching RPA...' : 'Trigger Host Containment'}</span>
                  </button>
                </div>
              )}

              {rpaSuccess && (
                <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-800 text-emerald-300 text-xs font-mono flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>{rpaSuccess}</span>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default URLAnalyzer;
