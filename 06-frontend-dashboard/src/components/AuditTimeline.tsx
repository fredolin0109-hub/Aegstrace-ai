import React from 'react';
import { CheckCircle2, Clock, AlertTriangle, Play, ShieldAlert, Cpu } from 'lucide-react';
import { AgentActionTraceItem, UiPathActionSummary } from '../types';

interface AuditTimelineProps {
  currentStage?: 'DETECTED' | 'ANALYZED' | 'INVESTIGATED' | 'DECIDED' | 'UIPATH_ACTION' | 'VERIFIED' | string;
  agentTraces?: AgentActionTraceItem[];
  uipathActions?: UiPathActionSummary[];
  className?: string;
  timestamp?: string;
}

const LIFECYCLE_STAGES = [
  { id: 'DETECTED', label: 'Detected', icon: Clock, desc: 'URL ingested & normalized' },
  { id: 'ANALYZED', label: 'Analyzed', icon: Cpu, desc: 'DSA Trie & ML heuristics run' },
  { id: 'INVESTIGATED', label: 'Investigated', icon: AlertTriangle, desc: 'Multi-provider intel & agent trace' },
  { id: 'DECIDED', label: 'Decided', icon: ShieldAlert, desc: 'Triage priority & action chosen' },
  { id: 'UIPATH_ACTION', label: 'UiPath Action', icon: Play, desc: 'Automated RPA response dispatched' },
  { id: 'VERIFIED', label: 'Verified', icon: CheckCircle2, desc: 'Host containment & loop verified' },
];

export const AuditTimeline: React.FC<AuditTimelineProps> = ({
  currentStage = 'ANALYZED',
  agentTraces = [],
  uipathActions = [],
  className = '',
  timestamp,
}) => {
  const normStage = currentStage.toUpperCase();

  // Find index of current stage
  const stageIndexMap: Record<string, number> = {
    'DETECTED': 0,
    'DETECT': 0,
    'ANALYZED': 1,
    'ANALYZE': 1,
    'INVESTIGATED': 2,
    'INVESTIGATE': 2,
    'DECIDED': 3,
    'DECIDE': 3,
    'UIPATH_ACTION': 4,
    'UIPATH ACTION': 4,
    'ACT': 4,
    'VERIFIED': 5,
    'VERIFY': 5,
  };

  const activeIdx = stageIndexMap[normStage] ?? 1;

  return (
    <div className={`rounded-xl bg-slate-900/90 border border-slate-800 p-6 ${className}`}>
      <div className="flex items-center justify-between pb-4 border-b border-slate-800/80 mb-6">
        <div>
          <h4 className="text-sm font-semibold font-mono tracking-wider text-slate-200 uppercase flex items-center gap-2">
            <span className="inline-block w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            Autonomous SOC Audit Lifecycle
          </h4>
          <p className="text-xs text-slate-400 mt-0.5">
            Immutable 6-Phase incident progression pipeline
          </p>
        </div>
        {timestamp && (
          <span className="text-[11px] font-mono text-slate-400 bg-slate-800/60 px-2.5 py-1 rounded border border-slate-700">
            {new Date(timestamp).toLocaleTimeString()}
          </span>
        )}
      </div>

      {/* Main horizontal stepper */}
      <div className="relative flex items-center justify-between">
        {/* Continuous connector line */}
        <div className="absolute top-5 left-6 right-6 h-0.5 bg-slate-800 -z-0" />
        <div
          className="absolute top-5 left-6 h-0.5 bg-gradient-to-r from-cyan-500 via-blue-500 to-emerald-500 -z-0 transition-all duration-700"
          style={{ width: `${(activeIdx / (LIFECYCLE_STAGES.length - 1)) * 100}%` }}
        />

        {LIFECYCLE_STAGES.map((stage, idx) => {
          const isPassed = idx < activeIdx;
          const isCurrent = idx === activeIdx;
          const Icon = stage.icon;

          return (
            <div key={stage.id} className="relative z-10 flex flex-col items-center flex-1">
              <div
                className={`w-10 h-10 rounded-full flex items-center justify-center border-2 transition-all duration-300 ${
                  isPassed
                    ? 'bg-cyan-950 border-cyan-500 text-cyan-400 shadow-[0_0_10px_rgba(6,182,212,0.4)]'
                    : isCurrent
                    ? 'bg-blue-950 border-blue-400 text-blue-300 animate-pulse shadow-[0_0_15px_rgba(59,130,246,0.6)]'
                    : 'bg-slate-900 border-slate-700 text-slate-500'
                }`}
              >
                <Icon className="w-5 h-5" />
              </div>
              <span
                className={`mt-2 text-xs font-mono font-medium tracking-wide text-center ${
                  isCurrent
                    ? 'text-cyan-300 font-bold'
                    : isPassed
                    ? 'text-slate-300'
                    : 'text-slate-500'
                }`}
              >
                {stage.label}
              </span>
              <span className="text-[10px] text-slate-500 text-center hidden md:inline-block max-w-[100px] mt-0.5">
                {stage.desc}
              </span>
            </div>
          );
        })}
      </div>

      {/* Sub-timeline for agent traces if available */}
      {agentTraces.length > 0 && (
        <div className="mt-8 pt-6 border-t border-slate-800">
          <h5 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-violet-400" />
            Agent Investigation Traces ({agentTraces.length} steps)
          </h5>
          <div className="space-y-2.5 max-h-56 overflow-y-auto pr-1">
            {agentTraces.map((trace, i) => (
              <div
                key={i}
                className="flex items-start gap-3 p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono"
              >
                <span className="text-[11px] px-1.5 py-0.5 rounded bg-violet-950 text-violet-300 border border-violet-800">
                  {trace.action_type}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-300">{trace.tool_name}</span>
                    <span className="text-[10px] text-slate-500">
                      {new Date(trace.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-slate-400 text-[11px] mt-0.5">{trace.decision_rationale}</p>
                </div>
                <span
                  className={`text-[10px] px-1.5 py-0.5 rounded ${
                    trace.status === 'SUCCESS' || trace.status === 'COMPLETED'
                      ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-800'
                      : 'bg-amber-950/60 text-amber-400 border border-amber-800'
                  }`}
                >
                  {trace.status}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Sub-timeline for UiPath Actions if available */}
      {uipathActions.length > 0 && (
        <div className="mt-6 pt-4 border-t border-slate-800">
          <h5 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            UiPath RPA Automated Responses ({uipathActions.length})
          </h5>
          <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
            {uipathActions.map((act) => (
              <div
                key={act.id}
                className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono"
              >
                <div className="flex items-center gap-2">
                  <Play className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="font-semibold text-slate-200">{act.action_type}</span>
                  <span className="text-slate-500 text-[11px]">({act.execution_id.slice(0, 8)}...)</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-slate-400">
                    {new Date(act.executed_at).toLocaleTimeString()}
                  </span>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded font-semibold uppercase ${
                      act.status === 'SUCCESS' || act.status === 'SIMULATED'
                        ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800'
                        : act.status === 'RUNNING'
                        ? 'bg-sky-950/80 text-sky-300 border border-sky-800 animate-pulse'
                        : 'bg-amber-950/80 text-amber-300 border border-amber-800'
                    }`}
                  >
                    {act.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default AuditTimeline;
