import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Search,
  Filter,
  Plus,
  RefreshCw,
  Zap,
  ArrowUpDown,
  X,
} from 'lucide-react';
import api from '../services/api';
import { IncidentResponse, IncidentCreate } from '../types';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';

export const Incidents: React.FC = () => {
  const navigate = useNavigate();

  const [incidents, setIncidents] = useState<IncidentResponse[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters & Sorting
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [sortBy, setSortBy] = useState<string>('priority');
  const [isTriageMode, setIsTriageMode] = useState<boolean>(false);

  // Pagination
  const [page, setPage] = useState(0);
  const pageSize = 15;

  // New Incident Modal
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [newIncidentData, setNewIncidentData] = useState<IncidentCreate>({
    url: '',
    title: '',
    description: '',
    severity: 'HIGH',
    assigned_to: 'ANALYST_SOC',
  });
  const [creatingIncident, setCreatingIncident] = useState(false);

  const fetchIncidents = async () => {
    setLoading(true);
    setError(null);
    try {
      if (isTriageMode) {
        const res = await api.getTriagedIncidents(statusFilter === 'ALL' ? 'OPEN' : statusFilter, 50);
        setIncidents(res.items);
        setTotal(res.total);
      } else {
        const res = await api.getIncidents({
          status: statusFilter,
          severity: severityFilter,
          search: searchQuery,
          sort_by: sortBy,
          skip: page * pageSize,
          limit: pageSize,
        });
        setIncidents(res.items);
        setTotal(res.total);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve incident records.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [statusFilter, severityFilter, sortBy, isTriageMode, page]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(0);
    fetchIncidents();
  };

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreatingIncident(true);
    try {
      await api.createIncident(newIncidentData);
      setIsModalOpen(false);
      setNewIncidentData({
        url: '',
        title: '',
        description: '',
        severity: 'HIGH',
        assigned_to: 'ANALYST_SOC',
      });
      fetchIncidents();
    } catch (err: any) {
      alert(`Error creating incident: ${err.message}`);
    } finally {
      setCreatingIncident(false);
    }
  };

  return (
    <div className="space-y-6 pb-16">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/90 p-6 rounded-xl border border-slate-800">
        <div>
          <h2 className="text-xl font-bold font-mono tracking-tight text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-rose-400" />
            INCIDENT COMMAND QUEUE
          </h2>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Triaged security events sorted via 02-dsa-engine Priority Max-Heap & Stable MergeSort.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsTriageMode(!isTriageMode)}
            className={`px-3.5 py-2 rounded-lg font-mono text-xs font-bold border flex items-center gap-2 transition-all ${
              isTriageMode
                ? 'bg-rose-950 text-rose-300 border-rose-700 shadow-[0_0_12px_rgba(244,63,94,0.4)]'
                : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
            }`}
          >
            <Zap className={`w-3.5 h-3.5 ${isTriageMode ? 'text-rose-400' : 'text-slate-400'}`} />
            <span>{isTriageMode ? 'DSA Triage Queue: ACTIVE' : 'Enable Triage Queue'}</span>
          </button>

          <button
            onClick={() => setIsModalOpen(true)}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-mono text-xs font-bold flex items-center gap-1.5 transition-all shadow-[0_0_15px_rgba(6,182,212,0.3)]"
          >
            <Plus className="w-4 h-4" />
            <span>Manual Incident</span>
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        {/* Search */}
        <form onSubmit={handleSearch} className="flex-1 min-w-[240px]">
          <div className="relative">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by incident #, title, or target URL..."
              className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-500 rounded-lg pl-9 pr-4 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none"
            />
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          </div>
        </form>

        {/* Dropdowns */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Status filter */}
          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(0);
              }}
              className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs font-mono focus:outline-none"
            >
              <option value="ALL">Status: All</option>
              <option value="OPEN">Status: OPEN</option>
              <option value="INVESTIGATING">Status: INVESTIGATING</option>
              <option value="CONTAINED">Status: CONTAINED</option>
              <option value="RESOLVED">Status: RESOLVED</option>
              <option value="FALSE_POSITIVE">Status: FALSE_POSITIVE</option>
            </select>
          </div>

          {/* Severity filter */}
          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(0);
              }}
              className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs font-mono focus:outline-none"
            >
              <option value="ALL">Severity: All</option>
              <option value="CRITICAL">Severity: CRITICAL</option>
              <option value="HIGH">Severity: HIGH</option>
              <option value="MEDIUM">Severity: MEDIUM</option>
              <option value="LOW">Severity: LOW</option>
            </select>
          </div>

          {/* Sort Strategy */}
          <div className="flex items-center gap-1.5 text-xs font-mono text-slate-400">
            <ArrowUpDown className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={sortBy}
              onChange={(e) => {
                setSortBy(e.target.value);
                setPage(0);
              }}
              disabled={isTriageMode}
              className="bg-slate-950 border border-slate-700 rounded-lg px-2.5 py-1.5 text-slate-200 text-xs font-mono focus:outline-none disabled:opacity-50"
            >
              <option value="priority">Sort: DSA Max-Heap Priority</option>
              <option value="severity">Sort: Stable MergeSort</option>
              <option value="recent">Sort: Most Recent</option>
            </select>
          </div>

          <button
            onClick={() => fetchIncidents()}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 border border-slate-700"
            title="Refresh incident list"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800 text-rose-300 text-xs font-mono">
          {error}
        </div>
      )}

      {/* Incidents Table */}
      <div className="rounded-xl bg-slate-900/90 border border-slate-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-3.5 px-4 font-semibold">Incident #</th>
                <th className="py-3.5 px-4 font-semibold">Severity</th>
                <th className="py-3.5 px-4 font-semibold">Status</th>
                <th className="py-3.5 px-4 font-semibold">Title & Target URL</th>
                <th className="py-3.5 px-4 font-semibold">Assigned</th>
                <th className="py-3.5 px-4 font-semibold">UiPath Actions</th>
                <th className="py-3.5 px-4 font-semibold">Logged</th>
                <th className="py-3.5 px-4 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 text-slate-300">
              {loading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-400" />
                    <span>Loading active security incidents...</span>
                  </td>
                </tr>
              ) : incidents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    No incidents matching the specified criteria.
                  </td>
                </tr>
              ) : (
                incidents.map((inc) => (
                  <tr
                    key={inc.id}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                    onClick={() => navigate(`/incidents/${inc.id}`)}
                  >
                    <td className="py-3.5 px-4 font-bold text-cyan-400 whitespace-nowrap">
                      {inc.incident_number}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <SeverityBadge severity={inc.severity} size="sm" />
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <StatusBadge status={inc.status} size="sm" />
                    </td>
                    <td className="py-3.5 px-4 max-w-xs truncate">
                      <div className="font-semibold text-slate-100 truncate">{inc.title}</div>
                      <div className="text-[11px] text-slate-400 truncate mt-0.5" title={inc.url}>
                        {inc.url}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">
                      {inc.assigned_to || 'UNASSIGNED'}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {inc.uipath_actions && inc.uipath_actions.length > 0 ? (
                        <div className="flex items-center gap-1.5">
                          <Zap className="w-3.5 h-3.5 text-emerald-400" />
                          <span className="text-[11px] text-emerald-300">
                            {inc.uipath_actions.length} action{inc.uipath_actions.length === 1 ? '' : 's'}
                          </span>
                        </div>
                      ) : (
                        <span className="text-slate-400 text-[11px]">None</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4 text-slate-400 text-[11px] whitespace-nowrap">
                      {new Date(inc.created_at).toLocaleDateString()}{' '}
                      {new Date(inc.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/incidents/${inc.id}`);
                        }}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-950 text-slate-300 hover:text-cyan-300 border border-slate-700 hover:border-cyan-700 text-[11px] font-mono transition-colors"
                      >
                        Details
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        {!isTriageMode && (
          <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between text-xs font-mono text-slate-400">
            <span>
              Showing {Math.min(total, page * pageSize + 1)} - {Math.min(total, (page + 1) * pageSize)} of {total} incidents
            </span>
            <div className="flex items-center gap-2">
              <button
                disabled={page === 0}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                className="px-3 py-1 rounded bg-slate-800 text-slate-300 disabled:opacity-40 hover:bg-slate-700"
              >
                Previous
              </button>
              <button
                disabled={(page + 1) * pageSize >= total}
                onClick={() => setPage((p) => p + 1)}
                className="px-3 py-1 rounded bg-slate-800 text-slate-300 disabled:opacity-40 hover:bg-slate-700"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Manual Incident Creation Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-xl bg-slate-900 border border-slate-700 p-6 shadow-2xl">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
              <h3 className="text-sm font-mono font-bold text-white flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                CREATE MANUAL SECURITY INCIDENT
              </h3>
              <button
                onClick={() => setIsModalOpen(false)}
                className="text-slate-400 hover:text-white p-1 rounded"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateIncident} className="space-y-4 text-xs font-mono">
              <div>
                <label className="block text-slate-400 mb-1">Target URL *</label>
                <input
                  type="text"
                  required
                  value={newIncidentData.url}
                  onChange={(e) => setNewIncidentData({ ...newIncidentData, url: e.target.value })}
                  placeholder="https://malicious-target.com/login"
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Incident Title *</label>
                <input
                  type="text"
                  required
                  value={newIncidentData.title}
                  onChange={(e) => setNewIncidentData({ ...newIncidentData, title: e.target.value })}
                  placeholder="Suspected Phishing Campaign: Executive Impersonation"
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">Description *</label>
                <textarea
                  required
                  rows={3}
                  value={newIncidentData.description}
                  onChange={(e) => setNewIncidentData({ ...newIncidentData, description: e.target.value })}
                  placeholder="Provide forensic context, observed phishing indicators, or attack vector..."
                  className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Initial Severity</label>
                  <select
                    value={newIncidentData.severity}
                    onChange={(e) => setNewIncidentData({ ...newIncidentData, severity: e.target.value as any })}
                    className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                  >
                    <option value="LOW">LOW</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1">Assigned Analyst</label>
                  <input
                    type="text"
                    value={newIncidentData.assigned_to || ''}
                    onChange={(e) => setNewIncidentData({ ...newIncidentData, assigned_to: e.target.value })}
                    placeholder="ANALYST_SOC"
                    className="w-full bg-slate-950 border border-slate-700 rounded px-3 py-2 text-slate-100"
                  />
                </div>
              </div>

              <div className="pt-3 flex justify-end gap-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingIncident}
                  className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold disabled:opacity-50"
                >
                  {creatingIncident ? 'Creating...' : 'Create Incident'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Incidents;
