import React, { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Zap,
  Play,
  CheckCircle2,
  Clock,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  User,
} from 'lucide-react';
import api from '../services/api';
import { IncidentResponse, UiPathStatusResponse } from '../types';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import AuditTimeline from '../components/AuditTimeline';

const UIPATH_ACTIONS = [
  { type: 'CONTAIN_HOST', label: 'Contain Host', desc: 'Isolate compromised endpoint network adapter' },
  { type: 'BLOCK_DOMAIN', label: 'Block Domain', desc: 'Push blacklist entry to perimeter DNS/proxy' },
  { type: 'CREATE_TICKET', label: 'Create Ticket', desc: 'Log P1 ticket in Jira / ServiceNow' },
  { type: 'NOTIFY_SOC', label: 'Notify SOC', desc: 'Dispatch priority alert to SOC War Room' },
  { type: 'ISOLATE_USER', label: 'Isolate User', desc: 'Revoke active sessions and force token reset' },
  { type: 'GENERATE_REPORT', label: 'Generate Report', desc: 'Compile forensic PDF threat dossier' },
];

export const IncidentDetails: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [incident, setIncident] = useState<IncidentResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Status update
  const [updatingStatus, setUpdatingStatus] = useState(false);

  // UiPath trigger & polling
  const [triggeringAction, setTriggeringAction] = useState<string | null>(null);
  const [activeExecutionId, setActiveExecutionId] = useState<string | null>(null);
  const [executionStatus, setExecutionStatus] = useState<UiPathStatusResponse | null>(null);
  const [rpaError, setRpaError] = useState<string | null>(null);

  const fetchIncident = async () => {
    if (!id) return;
    try {
      setError(null);
      const data = await api.getIncidentById(Number(id));
      setIncident(data);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve incident details.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncident();
  }, [id]);

  // Polling UiPath status if execution is active
  useEffect(() => {
    if (!activeExecutionId) return;

    const pollInterval = setInterval(async () => {
      try {
        const statusRes = await api.getUiPathStatus(activeExecutionId);
        setExecutionStatus(statusRes);

        if (['SUCCESS', 'FAILED', 'SIMULATED'].includes(statusRes.status.toUpperCase())) {
          clearInterval(pollInterval);
          fetchIncident(); // Refresh incident actions list
        }
      } catch (e: any) {
        console.error('Error polling UiPath execution:', e);
      }
    }, 1500);

    return () => clearInterval(pollInterval);
  }, [activeExecutionId]);

  const handleUpdateStatus = async (newStatus: string) => {
    if (!incident) return;
    setUpdatingStatus(true);
    try {
      const updated = await api.updateIncident(incident.id, { status: newStatus });
      setIncident(updated);
    } catch (err: any) {
      alert(`Status update failed: ${err.message}`);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleTriggerUiPath = async (actionType: string) => {
    if (!incident) return;
    setTriggeringAction(actionType);
    setRpaError(null);
    setExecutionStatus(null);

    try {
      const triggerRes = await api.triggerUiPathAction({
        incident_id: incident.id,
        action_type: actionType,
        parameters: {
          incident_number: incident.incident_number,
          target_url: incident.url,
          severity: incident.severity,
        },
      });
      setActiveExecutionId(triggerRes.execution_id);
    } catch (err: any) {
      setRpaError(err.message || 'Failed to dispatch UiPath workflow.');
    } finally {
      setTriggeringAction(null);
    }
  };

  if (loading) {
    return (
      <div className="p-16 text-center text-slate-400 font-mono text-xs">
        <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-3 text-cyan-400" />
        <p>Loading forensic incident #{id}...</p>
      </div>
    );
  }

  if (error || !incident) {
    return (
      <div className="p-8 rounded-xl bg-slate-900 border border-slate-800 font-mono text-xs text-rose-300">
        <div className="flex items-center gap-2 mb-4">
          <AlertTriangle className="w-5 h-5 text-rose-400" />
          <span className="font-bold">Incident Not Found</span>
        </div>
        <p className="text-slate-400 mb-6">{error || 'Unable to locate the specified incident.'}</p>
        <Link
          to="/incidents"
          className="px-4 py-2 rounded bg-slate-800 text-slate-200 hover:bg-slate-700 inline-flex items-center gap-2"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Return to Queue</span>
        </Link>
      </div>
    );
  }

  // Determine current stage for timeline
  const hasUiPathSuccess = incident.uipath_actions.some((a) =>
    ['SUCCESS', 'SIMULATED'].includes(a.status.toUpperCase())
  );
  const currentStage = incident.status === 'RESOLVED'
    ? 'VERIFIED'
    : hasUiPathSuccess
    ? 'VERIFIED'
    : incident.uipath_actions.length > 0
    ? 'UIPATH_ACTION'
    : incident.status === 'CONTAINED'
    ? 'UIPATH_ACTION'
    : 'DECIDED';

  return (
    <div className="space-y-6 pb-20">
      {/* Top Breadcrumb & Controls */}
      <div className="flex items-center justify-between">
        <Link
          to="/incidents"
          className="inline-flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-cyan-400 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Incident Command Queue</span>
        </Link>

        {/* Quick status selector */}
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-slate-400">Change Status:</span>
          <select
            value={incident.status}
            disabled={updatingStatus}
            onChange={(e) => handleUpdateStatus(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono disabled:opacity-50"
          >
            <option value="OPEN">OPEN</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="CONTAINED">CONTAINED</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="FALSE_POSITIVE">FALSE_POSITIVE</option>
          </select>
        </div>
      </div>

      {/* Incident Header Card */}
      <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-6 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4 pb-6 border-b border-slate-800">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <span className="text-lg font-bold font-mono text-cyan-400">
                {incident.incident_number}
              </span>
              <SeverityBadge severity={incident.severity} size="md" />
              <StatusBadge status={incident.status} size="md" />
            </div>
            <h1 className="text-xl font-bold text-white font-mono mt-1">
              {incident.title}
            </h1>
            <p className="text-xs text-slate-400 font-mono max-w-2xl leading-relaxed pt-1">
              {incident.description}
            </p>
          </div>

          <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800 text-xs font-mono space-y-2 min-w-[240px]">
            <div className="flex justify-between">
              <span className="text-slate-400">Assigned Analyst:</span>
              <span className="text-slate-200 font-semibold flex items-center gap-1">
                <User className="w-3.5 h-3.5 text-cyan-400" />
                {incident.assigned_to || 'UNASSIGNED'}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Created:</span>
              <span className="text-slate-300">
                {new Date(incident.created_at).toLocaleString()}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Last Updated:</span>
              <span className="text-slate-300">
                {new Date(incident.updated_at).toLocaleString()}
              </span>
            </div>
          </div>
        </div>

        {/* Target URL Reference */}
        <div className="mt-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono bg-slate-950/60 p-3 rounded-lg border border-slate-800/80">
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-slate-400 uppercase text-[10px] tracking-wider flex-shrink-0">
              TARGET URL:
            </span>
            <span className="text-slate-200 truncate font-semibold" title={incident.url}>
              {incident.url}
            </span>
          </div>

          <div className="flex items-center gap-3 flex-shrink-0">
            <Link
              to={`/analyze?url=${encodeURIComponent(incident.url)}`}
              className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px]"
            >
              <span>Inspect in Analyzer</span>
              <ExternalLink className="w-3 h-3" />
            </Link>
          </div>
        </div>
      </div>

      {/* 6-Phase SOC Audit Timeline */}
      <AuditTimeline
        currentStage={currentStage}
        uipathActions={incident.uipath_actions}
        timestamp={incident.created_at}
      />

      {/* Interactive UiPath RPA Response Dispatcher */}
      <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-6 shadow-xl">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-6">
          <div>
            <h3 className="text-base font-bold font-mono text-white flex items-center gap-2">
              <Zap className="w-5 h-5 text-emerald-400" />
              UIPATH RPA AUTOMATED RESPONSE DISPATCHER
            </h3>
            <p className="text-xs font-mono text-slate-400 mt-0.5">
              Select an authorized security orchestration playbook to execute automated containment.
            </p>
          </div>

          <span className="text-xs font-mono px-3 py-1 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800">
            ENGINE: ACTIVE (DEMO MODE)
          </span>
        </div>

        {rpaError && (
          <div className="mb-6 p-3 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-300 text-xs font-mono flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
            <span>{rpaError}</span>
          </div>
        )}

        {/* Live Execution Telemetry Bar if running or finished */}
        {activeExecutionId && (
          <div className="mb-6 p-4 rounded-xl bg-slate-950 border border-cyan-800/80 text-xs font-mono space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-cyan-300 font-bold flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                Live Execution: {activeExecutionId}
              </span>
              <span
                className={`px-2 py-0.5 rounded font-bold uppercase ${
                  executionStatus?.status === 'SUCCESS' || executionStatus?.status === 'SIMULATED'
                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                    : executionStatus?.status === 'FAILED'
                    ? 'bg-rose-950 text-rose-300 border border-rose-700'
                    : 'bg-sky-950 text-sky-300 border border-sky-700 animate-pulse'
                }`}
              >
                {executionStatus?.status || 'INITIALIZING'}
              </span>
            </div>

            {/* Progress Bar */}
            <div className="w-full bg-slate-900 h-2 rounded-full overflow-hidden">
              <div
                className="bg-gradient-to-r from-cyan-500 to-emerald-500 h-full transition-all duration-300"
                style={{ width: `${executionStatus?.progress_percentage ?? 25}%` }}
              />
            </div>

            <div className="flex justify-between text-[11px] text-slate-400">
              <span>Action: {executionStatus?.action_type || 'RPA Workflow'}</span>
              <span>Progress: {executionStatus?.progress_percentage ?? 25}%</span>
            </div>

            {executionStatus?.result && (
              <div className="p-2.5 rounded bg-slate-900 border border-slate-800 text-[11px] text-slate-300">
                <span className="text-slate-400 block mb-1 uppercase font-semibold">Execution Output:</span>
                <pre className="text-emerald-400 whitespace-pre-wrap overflow-x-auto">
                  {JSON.stringify(executionStatus.result, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}

        {/* 6 RPA Action Buttons */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {UIPATH_ACTIONS.map((action) => {
            const isThisTriggering = triggeringAction === action.type;

            return (
              <div
                key={action.type}
                className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono font-bold text-slate-200">
                      {action.label}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                      PLAYBOOK
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 font-mono leading-relaxed mb-4">
                    {action.desc}
                  </p>
                </div>

                <button
                  onClick={() => handleTriggerUiPath(action.type)}
                  disabled={Boolean(triggeringAction) || Boolean(activeExecutionId && executionStatus?.status === 'RUNNING')}
                  className="w-full py-2 px-3 rounded-lg bg-slate-900 hover:bg-emerald-950 text-slate-300 hover:text-emerald-300 border border-slate-700 hover:border-emerald-700 font-mono text-xs font-semibold flex items-center justify-center gap-2 transition-all disabled:opacity-50"
                >
                  {isThisTriggering ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Dispatching...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Execute Workflow</span>
                    </>
                  )}
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* Incident RPA Execution History Table */}
      <div className="rounded-xl bg-slate-900/90 border border-slate-800 p-6">
        <h4 className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider mb-4 flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          RPA Execution Audit Log ({incident.uipath_actions.length})
        </h4>

        {incident.uipath_actions.length === 0 ? (
          <p className="text-xs font-mono text-slate-400 p-6 text-center">
            No automated RPA containment playbooks executed yet for this incident.
          </p>
        ) : (
          <div className="space-y-2.5">
            {incident.uipath_actions.map((act) => (
              <div
                key={act.id}
                className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 flex items-center justify-between gap-3 text-xs font-mono"
              >
                <div className="flex items-center gap-3">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <div>
                    <span className="font-bold text-slate-200">{act.action_type}</span>
                    <span className="text-slate-400 text-[11px] block mt-0.5">
                      Execution ID: {act.execution_id}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-4 text-right">
                  <div>
                    <span className="text-[11px] text-slate-400 block">
                      {new Date(act.executed_at).toLocaleString()}
                    </span>
                    {act.completed_at && (
                      <span className="text-[10px] text-slate-400 block">
                        Duration: ~
                        {Math.max(
                          1,
                          Math.round(
                            (new Date(act.completed_at).getTime() - new Date(act.executed_at).getTime()) / 1000
                          )
                        )}
                        s
                      </span>
                    )}
                  </div>
                  <span
                    className={`px-2.5 py-1 rounded font-bold uppercase text-[11px] ${
                      act.status === 'SUCCESS' || act.status === 'SIMULATED'
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        : act.status === 'RUNNING'
                        ? 'bg-sky-950 text-sky-300 border border-sky-800 animate-pulse'
                        : 'bg-rose-950 text-rose-300 border border-rose-800'
                    }`}
                  >
                    {act.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default IncidentDetails;
